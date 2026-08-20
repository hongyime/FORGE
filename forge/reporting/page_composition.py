"""HTML page composition helpers for static dashboard pages."""
from __future__ import annotations

import html
from collections.abc import Callable
from pathlib import Path
from typing import Any

DEFAULT_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
ENGAGEMENT_SECTION_TITLES = {
    "evidence_provenance": "Evidence Provenance Summary",
    "hosts": "Recent Hosts",
    "emails": "Recent Emails",
    "email_intelligence": "Email Intelligence",
    "account_existence": "Account Existence",
    "cti_observations": "CTI / OSINT Observations",
    "engagement_seeds": "Engagement Seeds",
    "seed_runs": "Recent Seed Runs",
    "engagement_runs": "Recent Engagement Runs",
    "target_resume_candidate": "Target Resume Review Candidate",
    "distributed_tasks": "Distributed Task Queue",
    "services": "Recent Services",
    "key_scanner_findings": "Recent Key Findings",
    "secret_lifecycle_items": "Secret Lifecycle",
    "cloud_assets": "Cloud Asset Inventory",
    "artifact_queue": "Queued Artifacts",
    "crawl_results": "Recent Web Crawl Results",
    "social_profiles": "Recent Social Profiles",
    "port_scan_results": "Recent Port Scan Results",
    "passive_vulns": "Recent Passive Vulnerabilities",
    "vulnerability_findings": "Recent Vulnerability Findings",
    "auth_test_results": "Recent Auth Test Results",
    "cloud_validation_results": "Cloud Validation Results",
    "monitoring_policies": "Monitoring Policies",
    "monitoring_alert_routes": "Monitoring Alert Routes",
    "monitoring_alert_suppressions": "Monitoring Alert Suppressions",
    "remediation_items": "Remediation Workflow",
    "retention_policies": "Retention Policies",
    "retention_runs": "Retention Runs",
    "retention_run_items": "Retention Run Items",
    "asset_entities": "Asset Graph Entities",
    "asset_relationships": "Asset Graph Relationships",
    "asset_ownership_claims": "Asset Ownership Claims",
    "asset_ownership_conflicts": "Asset Ownership Conflicts",
    "asset_graph_attack_paths": "Asset Graph Attack Paths",
    "asset_graph_choke_points": "Asset Graph Choke Points",
    "asset_graph_fix_candidates": "Asset Graph Fix Candidates",
    "active_validation_coverage": "Active Validation Coverage",
    "active_validation_jobs": "Active Validation Jobs",
    "active_validation_runs": "Active Validation Runs",
    "monitoring_snapshots": "Monitoring Snapshot Trend",
    "monitoring_trend_points": "Monitoring Trend Aggregates",
    "monitoring_changes": "Monitoring Exposure Changes",
    "monitoring_alerts": "Monitoring Alerts",
    "scope_denials": "Scope Boundary Denials",
    "audit_log": "Recent Audit Log",
}


def _overview_status_options(engagements: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str(item.get("status") or "unknown").strip() or "unknown"
            for item in engagements
        },
        key=lambda value: value.lower(),
    )


def _overview_tag_options(engagements: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            tag
            for item in engagements
            for tag in item.get("tags", [])
        },
        key=lambda value: value.casefold(),
    )


def _overview_report_note(
    item: dict[str, Any],
    *,
    report_count: int,
) -> tuple[str, str, str, str, str]:
    report_summary = item.get("report_summary") or {}
    report_rendered = str(
        report_summary.get("rendered_provider")
        or report_summary.get("provider")
        or report_summary.get("render_backend")
        or "-"
    )
    report_backend = str(report_summary.get("render_backend") or "").strip()
    report_export_count = int(
        report_summary.get("export_count")
        or len(report_summary.get("available_exports") or [])
        or report_count
    )
    report_note = (
        f"{report_rendered} \N{MIDDLE DOT} {report_export_count} exports"
        if report_summary
        else "no report summary"
    )
    if report_backend and report_backend != report_rendered:
        report_note = f"{report_note} \N{MIDDLE DOT} backend {report_backend}"
    if int(item.get("report_family_count", 0) or 0) > 1:
        report_note = (
            f"{report_note} \N{MIDDLE DOT} "
            f"{int(item.get('report_family_count', 0) or 0)} families"
        )
    if report_summary.get("raw_export"):
        report_note = f"{report_note} \N{MIDDLE DOT} raw"
    if report_summary.get("fallback_reason"):
        report_note = f"{report_note} \N{MIDDLE DOT} fallback"
    report_raw_export = "1" if report_summary.get("raw_export") else "0"
    report_fallback = "1" if report_summary.get("fallback_reason") else "0"
    report_degraded = "1" if report_summary.get("report_write_error") else "0"
    report_prior = "1" if item.get("has_prior_report_generations") else "0"
    return report_note, report_raw_export, report_fallback, report_degraded, report_prior


def _overview_table_row(
    item: dict[str, Any],
    output_path: Path,
    *,
    relative_href: Callable[[Path, Path], str],
    severity_summary_text: Callable[[dict[str, int]], str],
    timestamp_epoch_ms: Callable[[str], int],
    severity_order: tuple[str, ...],
) -> str:
    detail_href = relative_href(output_path, item["detail_page"])
    seed_text = ", ".join(item["seeds"][:2]) or item["primary_seed"] or "-"
    if len(item["seeds"]) > 2:
        seed_text = f"{seed_text} (+{len(item['seeds']) - 2})"
    graph_badge = (
        f'<span class="pill accent">nodes {item["graph_summary"].get("nodes", 0)}</span>'
        if item["graph_summary"]
        else '<span class="pill">none</span>'
    )
    status = item["status"] or "unknown"
    severity_text = severity_summary_text(item["severity_summary"])
    latest_activity = item["latest_audit"] or item["updated_at"] or ""
    updated_ms = timestamp_epoch_ms(latest_activity)
    severity_counts = item.get("severity_summary", {})
    finding_count = sum(
        int(severity_counts.get(level, 0) or 0)
        for level in severity_order
    )
    tags = item.get("tags", [])
    tag_text = ", ".join(str(tag) for tag in tags)
    row_meta = str(item["operator"] or "-")
    if tag_text:
        row_meta = f"{row_meta} \N{MIDDLE DOT} {tag_text}"
    tag_keys = "|".join(str(tag).casefold() for tag in tags)
    report_count = len(item["report_files"])
    (
        report_note,
        report_raw_export,
        report_fallback,
        report_degraded,
        report_prior,
    ) = _overview_report_note(item, report_count=report_count)
    resume_candidate = item.get("target_resume_candidate") or {}
    resume_reason = str(resume_candidate.get("reason") or "")
    resume_status = str(resume_candidate.get("status") or "")
    resume_pending = int(resume_candidate.get("pending_work_total") or 0)
    resume_ready = bool(resume_candidate.get("resume_ready"))
    resume_blockers = [
        str(item) for item in (resume_candidate.get("resume_blockers") or [])[:3]
    ]
    resume_review = "1" if resume_reason else "0"
    if resume_reason:
        resume_note = f"{resume_reason} \N{MIDDLE DOT} {resume_status}"
        if resume_pending:
            resume_note = f"{resume_note} \N{MIDDLE DOT} pending {resume_pending}"
        if resume_blockers:
            resume_note = f"{resume_note} \N{MIDDLE DOT} blocked: {', '.join(resume_blockers)}"
        resume_label = "ready" if resume_ready else "blocked"
        resume_class = "pill" if resume_ready else "pill warn"
        resume_html = (
            f"<span class='{resume_class}'>{html.escape(resume_label)}</span>"
            f"<div class='tiny muted'>{html.escape(resume_note)}</div>"
        )
    else:
        resume_html = "<span class='pill'>ok</span>"
    return (
        "<tr class='eng-row'"
        f" data-status='{html.escape(str(status))}'"
        f" data-severity='{html.escape(str(item['highest_severity']))}'"
        f" data-tags='{html.escape(tag_keys)}'"
        f" data-updated-ms='{updated_ms}'"
        f" data-finding-count='{finding_count}'"
        f" data-report-raw='{report_raw_export}'"
        f" data-report-fallback='{report_fallback}'"
        f" data-report-degraded='{report_degraded}'"
        f" data-report-prior='{report_prior}'"
        f" data-resume-review='{resume_review}'>"
        f"<td><a class='eng-link' href='{html.escape(detail_href)}'>{html.escape(item['id'])}</a></td>"
        f"<td><strong>{html.escape(item['name'])}</strong><div class='tiny muted'>{html.escape(row_meta)}</div></td>"
        f"<td><span class='mono tiny'>{html.escape(seed_text)}</span></td>"
        f"<td><span class='pill'>{html.escape(status)}</span></td>"
        f"<td><span class='pill warn'>{html.escape(item['highest_severity'])}</span><div class='tiny muted'>{html.escape(severity_text)}</div></td>"
        f"<td class='right'>{int(item['counts'].get('hosts', 0))}</td>"
        f"<td class='right'>{int(item['counts'].get('emails', 0))}</td>"
        f"<td class='right'>{int(item['counts'].get('services', 0))}</td>"
        f"<td class='right'>{report_count}<div class='tiny muted'>{html.escape(report_note)}</div></td>"
        f"<td>{graph_badge}</td>"
        f"<td>{resume_html}</td>"
        f"<td class='tiny'>{html.escape(item['latest_audit'] or item['updated_at'] or '-')}</td>"
        f"<td class='tiny mono'>{html.escape(item['slug'])}</td>"
        "</tr>"
    )


def render_overview_page(
    engagements: list[dict[str, Any]],
    output_path: Path,
    generated_at: str,
    *,
    base_styles: str,
    relative_href: Callable[[Path, Path], str],
    severity_summary_text: Callable[[dict[str, int]], str],
    timestamp_epoch_ms: Callable[[str], int],
    severity_order: tuple[str, ...] = DEFAULT_SEVERITY_ORDER,
) -> str:
    """Render the static dashboard overview page."""
    total_reports = sum(len(item["report_files"]) for item in engagements)
    total_graphs = sum(1 for item in engagements if item["graph_files"])
    total_hosts = sum(int(item["counts"].get("hosts", 0)) for item in engagements)
    total_emails = sum(int(item["counts"].get("emails", 0)) for item in engagements)
    total_services = sum(int(item["counts"].get("services", 0)) for item in engagements)
    total_resume_reviews = sum(1 for item in engagements if item.get("target_resume_candidate"))
    total_critical = sum(
        int(item["severity_summary"].get("CRITICAL", 0))
        for item in engagements
    )
    total_high = sum(
        int(item["severity_summary"].get("HIGH", 0))
        for item in engagements
    )
    status_options = _overview_status_options(engagements)
    tag_options = _overview_tag_options(engagements)

    rows = [
        _overview_table_row(
            item,
            output_path,
            relative_href=relative_href,
            severity_summary_text=severity_summary_text,
            timestamp_epoch_ms=timestamp_epoch_ms,
            severity_order=severity_order,
        )
        for item in engagements
    ]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FORGE Dashboard</title>
  <style>{base_styles}</style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div>
        <div class="chips">
          <span class="chip">FORGE engagement index</span>
          <span class="chip">detail pages per engagement</span>
        </div>
        <h1>Dashboard</h1>
        <p class="muted">The overview stays compact. Each engagement now opens into its own static page for reports, graph artifacts, audit history, and evidence tables.</p>
      </div>
      <div class="hero-meta">
        <div class="stamp">Generated</div>
        <div>{html.escape(generated_at)}</div>
        <div class="stamp">Entry file: {html.escape(output_path.name)}</div>
      </div>
    </section>

    <section class="stats">
      <div class="stat"><div class="label">Engagements</div><div class="value">{len(engagements)}</div></div>
      <div class="stat"><div class="label">Critical</div><div class="value">{total_critical}</div></div>
      <div class="stat"><div class="label">High</div><div class="value">{total_high}</div></div>
      <div class="stat"><div class="label">Reports</div><div class="value">{total_reports}</div></div>
      <div class="stat"><div class="label">Graphs</div><div class="value">{total_graphs}</div></div>
      <div class="stat"><div class="label">Resume Review</div><div class="value">{total_resume_reviews}</div></div>
      <div class="stat"><div class="label">Hosts</div><div class="value">{total_hosts}</div></div>
      <div class="stat"><div class="label">Emails</div><div class="value">{total_emails}</div></div>
      <div class="stat"><div class="label">Services</div><div class="value">{total_services}</div></div>
    </section>

    <section class="panel">
      <div class="panel-head toolbar">
        <h2>Engagements</h2>
        <div>
          <input id="filter" class="search" type="search" placeholder="Filter by id, name, seed, operator, status, slug" oninput="filterRows()">
          <select id="status-filter" class="search" onchange="filterRows()">
            <option value="ALL">All statuses</option>
            {''.join(f"<option value='{html.escape(status)}'>{html.escape(status)}</option>" for status in status_options)}
          </select>
          <select id="severity-filter" class="search" onchange="filterRows()">
            <option value="ALL">All severities</option>
            <option value="CRITICAL">Has critical</option>
            <option value="HIGH_PLUS">Has high or critical</option>
            <option value="MEDIUM_PLUS">Has medium or above</option>
            <option value="FINDINGS">Any finding rows</option>
          </select>
          <select id="tag-filter" class="search" onchange="filterRows()">
            <option value="ALL">All tags</option>
            {''.join(f"<option value='{html.escape(tag.casefold())}'>{html.escape(tag)}</option>" for tag in tag_options)}
          </select>
          <select id="report-state-filter" class="search" onchange="filterRows()">
            <option value="ALL">All report states</option>
            <option value="PRIOR">Has prior reports</option>
            <option value="RAW_EXPORT">Raw export fallback</option>
            <option value="FALLBACK">Fallback reason</option>
            <option value="DEGRADED">Write degraded</option>
            <option value="RESUME_REVIEW">Resume review</option>
          </select>
          <input id="updated-after-filter" class="search" type="date" onchange="filterRows()" oninput="filterRows()" title="Updated on or after">
          <input id="updated-before-filter" class="search" type="date" onchange="filterRows()" oninput="filterRows()" title="Updated on or before">
          <select id="recency-filter" class="search" onchange="filterRows()">
            <option value="ALL">Any recency</option>
            <option value="24H">Updated in 24h</option>
            <option value="7D">Updated in 7d</option>
            <option value="30D">Updated in 30d</option>
            <option value="STALE_30D">Stale over 30d</option>
          </select>
          <span id="filter-state" class="tiny muted"></span>
        </div>
      </div>
      <div class="panel-body" style="padding:0">
        <table id="engagement-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Seeds</th>
              <th>Status</th>
              <th>Severity</th>
              <th class="right">Hosts</th>
              <th class="right">Emails</th>
              <th class="right">Services</th>
              <th class="right">Reports</th>
              <th>Graph</th>
              <th>Run Review</th>
              <th>Latest audit</th>
              <th>Slug</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows) if rows else '<tr><td colspan="13"><div class="empty">No engagement databases were found.</div></td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    const OVERVIEW_FILTERS_KEY = 'forge.overviewFilters';
    function readSavedFilters() {{
      try {{
        const raw = window.localStorage.getItem(OVERVIEW_FILTERS_KEY);
        if (!raw) return {{}};
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === 'object' ? parsed : {{}};
      }} catch (_error) {{
        return {{}};
      }}
    }}
    function writeSavedFilters(state) {{
      try {{
        const isDefaultState =
          !state.q &&
          (state.statusFilter || 'ALL') === 'ALL' &&
          (state.severityFilter || 'ALL') === 'ALL' &&
          (state.tagFilter || 'ALL') === 'ALL' &&
          (state.reportStateFilter || 'ALL') === 'ALL' &&
          !state.updatedAfterValue &&
          !state.updatedBeforeValue &&
          (state.recencyFilter || 'ALL') === 'ALL';
        if (isDefaultState) {{
          window.localStorage.removeItem(OVERVIEW_FILTERS_KEY);
          return;
        }}
        window.localStorage.setItem(OVERVIEW_FILTERS_KEY, JSON.stringify(state));
      }} catch (_error) {{
        return;
      }}
    }}
    function applySavedFilters() {{
      const saved = readSavedFilters();
      const textFilter = document.getElementById('filter');
      const statusFilter = document.getElementById('status-filter');
      const severityFilter = document.getElementById('severity-filter');
      const tagFilter = document.getElementById('tag-filter');
      const reportStateFilter = document.getElementById('report-state-filter');
      const updatedAfterFilter = document.getElementById('updated-after-filter');
      const updatedBeforeFilter = document.getElementById('updated-before-filter');
      const recencyFilter = document.getElementById('recency-filter');
      if (typeof saved.q === 'string') textFilter.value = saved.q;
      if (typeof saved.statusFilter === 'string') statusFilter.value = saved.statusFilter;
      if (typeof saved.severityFilter === 'string') severityFilter.value = saved.severityFilter;
      if (typeof saved.tagFilter === 'string') tagFilter.value = saved.tagFilter;
      if (typeof saved.reportStateFilter === 'string') reportStateFilter.value = saved.reportStateFilter;
      if (typeof saved.updatedAfterValue === 'string') updatedAfterFilter.value = saved.updatedAfterValue;
      if (typeof saved.updatedBeforeValue === 'string') updatedBeforeFilter.value = saved.updatedBeforeValue;
      if (typeof saved.recencyFilter === 'string') recencyFilter.value = saved.recencyFilter;
    }}
    function filterRows() {{
      const q = document.getElementById('filter').value.toLowerCase().trim();
      const statusFilter = document.getElementById('status-filter').value;
      const severityFilter = document.getElementById('severity-filter').value;
      const tagFilter = document.getElementById('tag-filter').value;
      const reportStateFilter = document.getElementById('report-state-filter').value;
      const updatedAfterValue = document.getElementById('updated-after-filter').value;
      const updatedBeforeValue = document.getElementById('updated-before-filter').value;
      const recencyFilter = document.getElementById('recency-filter').value;
      const rows = Array.from(document.querySelectorAll('#engagement-table tbody tr.eng-row'));
      const now = Date.now();
      const updatedAfterMs = updatedAfterValue ? Date.parse(`${{updatedAfterValue}}T00:00:00`) : 0;
      const updatedBeforeMs = updatedBeforeValue ? Date.parse(`${{updatedBeforeValue}}T23:59:59.999`) : 0;
      let visible = 0;
      rows.forEach((row) => {{
        const status = (row.dataset.status || 'unknown').trim();
        const highestSeverity = (row.dataset.severity || 'INFO').trim().toUpperCase();
        const rowTags = (row.dataset.tags || '').split('|').filter(Boolean);
        const findingCount = Number(row.dataset.findingCount || '0');
        const updatedMs = Number(row.dataset.updatedMs || '0');
        const statusMatch = statusFilter === 'ALL' || status === statusFilter;
        const severityMatch =
          severityFilter === 'ALL' ||
          (severityFilter === 'CRITICAL' && highestSeverity === 'CRITICAL') ||
          (severityFilter === 'HIGH_PLUS' && ['CRITICAL', 'HIGH'].includes(highestSeverity)) ||
          (severityFilter === 'MEDIUM_PLUS' && ['CRITICAL', 'HIGH', 'MEDIUM'].includes(highestSeverity)) ||
          (severityFilter === 'FINDINGS' && findingCount > 0);
        const tagMatch = tagFilter === 'ALL' || rowTags.includes(tagFilter);
        const reportStateMatch =
          reportStateFilter === 'ALL' ||
          (reportStateFilter === 'PRIOR' && row.dataset.reportPrior === '1') ||
          (reportStateFilter === 'RAW_EXPORT' && row.dataset.reportRaw === '1') ||
          (reportStateFilter === 'FALLBACK' && row.dataset.reportFallback === '1') ||
          (reportStateFilter === 'DEGRADED' && row.dataset.reportDegraded === '1') ||
          (reportStateFilter === 'RESUME_REVIEW' && row.dataset.resumeReview === '1');
        const dateRangeMatch =
          (!updatedAfterValue || (updatedMs > 0 && !Number.isNaN(updatedAfterMs) && updatedMs >= updatedAfterMs)) &&
          (!updatedBeforeValue || (updatedMs > 0 && !Number.isNaN(updatedBeforeMs) && updatedMs <= updatedBeforeMs));
        const recencyMatch =
          recencyFilter === 'ALL' ||
          (recencyFilter === '24H' && updatedMs > 0 && now - updatedMs <= 24 * 60 * 60 * 1000) ||
          (recencyFilter === '7D' && updatedMs > 0 && now - updatedMs <= 7 * 24 * 60 * 60 * 1000) ||
          (recencyFilter === '30D' && updatedMs > 0 && now - updatedMs <= 30 * 24 * 60 * 60 * 1000) ||
          (recencyFilter === 'STALE_30D' && (!updatedMs || now - updatedMs > 30 * 24 * 60 * 60 * 1000));
        const searchableText = `${{row.textContent}} ${{row.dataset.tags || ''}}`.toLowerCase();
        const queryMatch = !q || searchableText.includes(q);
        const match = statusMatch && severityMatch && tagMatch && reportStateMatch && dateRangeMatch && recencyMatch && queryMatch;
        row.classList.toggle('hide', !match);
        if (match) visible += 1;
      }});
      writeSavedFilters({{
        q,
        statusFilter,
        severityFilter,
        tagFilter,
        reportStateFilter,
        updatedAfterValue,
        updatedBeforeValue,
        recencyFilter,
      }});
      document.getElementById('filter-state').textContent = `${{visible}} / ${{rows.length}} match`;
    }}
    applySavedFilters();
    filterRows();
  </script>
</body>
</html>
"""


def render_engagement_evidence_sections(
    sections: dict[str, list[dict[str, str]]],
    *,
    render_table: Callable[[str, list[dict[str, str]]], str],
) -> str:
    """Render ordered evidence tables for an engagement detail page."""
    return "".join(
        render_table(title, sections.get(key, []))
        for key, title in ENGAGEMENT_SECTION_TITLES.items()
    )


def render_engagement_detail_page(
    engagement: dict[str, Any],
    index_path: Path,
    page_path: Path,
    *,
    base_styles: str,
    relative_href: Callable[[Path, Path], str],
    format_size: Callable[[int], str],
    severity_order: tuple[str, ...],
    meta_blocks: list[str],
    seed_html: str,
    scope_html: str,
    artifact_block: str,
    report_callout_html: str,
    graph_stage_html: str,
    graph_summary_html: str,
    operational_timeline_html: str,
    audit_timeline_html: str,
    evidence_sections_html: str,
    report_history_html: str,
    report_previews_html: str,
) -> str:
    """Render the static engagement detail page shell."""
    counts = engagement["counts"]
    severity_summary = engagement.get("severity_summary", {})
    highest_severity = engagement.get("highest_severity", "INFO")
    graph_files = engagement["graph_files"]
    report_files = engagement["report_files"]
    audit_files = engagement.get("audit_files", [])
    run_summary = engagement.get("run_summary") or {}
    asset_graph_summary = engagement.get("asset_graph_summary") or {}
    signal_count = int(
        sum(int(severity_summary.get(level, 0)) for level in severity_order)
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FORGE {html.escape(engagement['id'])}</title>
  <style>{base_styles}</style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div>
        <a class="backlink" href="{html.escape(relative_href(page_path, index_path))}">\N{LEFTWARDS ARROW} Back to dashboard</a>
        <div class="chips" style="margin-top:14px">
          <span class="chip">engagement {html.escape(engagement['id'])}</span>
          <span class="chip">{html.escape(engagement['status'] or 'unknown')}</span>
          <span class="chip">{len(report_files)} reports</span>
          <span class="chip">{len(graph_files)} graph artifacts</span>
          <span class="chip">{len(audit_files)} audit artifacts</span>
          {''.join(f'<span class="chip">{html.escape(str(tag))}</span>' for tag in engagement.get('tags', []))}
        </div>
        <h1>{html.escape(engagement['name'])}</h1>
        <p class="muted">Primary seed: <span class="mono">{html.escape(engagement['primary_seed'] or '-')}</span></p>
      </div>
      <div class="hero-meta">
        <div class="stamp">Latest audit</div>
        <div>{html.escape(engagement['latest_audit'] or engagement['updated_at'] or '-')}</div>
        <div class="stamp">DB size: {html.escape(format_size(int(engagement['size_bytes'] or 0)))}</div>
      </div>
    </section>

    <section class="stats">
      <div class="stat"><div class="label">Hosts</div><div class="value">{int(counts.get('hosts', 0))}</div></div>
      <div class="stat"><div class="label">Emails</div><div class="value">{int(counts.get('emails', 0))}</div></div>
      <div class="stat"><div class="label">Services</div><div class="value">{int(counts.get('services', 0))}</div></div>
      <div class="stat"><div class="label">Graph nodes / owners</div><div class="value">{int(asset_graph_summary.get('node_count', 0) or 0)} / {int(asset_graph_summary.get('active_owner_count', 0) or 0)}</div></div>
      <div class="stat"><div class="label">Owner conflicts</div><div class="value">{int(asset_graph_summary.get('ownership_conflict_count', 0) or 0)}</div></div>
      <div class="stat"><div class="label">Graph paths / choke points</div><div class="value">{int(asset_graph_summary.get('attack_path_count', 0) or 0)} / {int(asset_graph_summary.get('choke_point_count', 0) or 0)}</div></div>
      <div class="stat"><div class="label">Highest severity</div><div class="value">{html.escape(str(highest_severity))}</div></div>
      <div class="stat"><div class="label">Critical / High</div><div class="value">{int(severity_summary.get('CRITICAL', 0))} / {int(severity_summary.get('HIGH', 0))}</div></div>
      <div class="stat"><div class="label">Audit rows</div><div class="value">{int(counts.get('audit_log', 0))}</div></div>
      <div class="stat"><div class="label">Run status</div><div class="value">{html.escape(str(run_summary.get('status', 'untracked')))}</div></div>
    </section>

    <div class="section-stack">
      <section class="panel">
        <div class="panel-head"><h2>Metadata</h2></div>
        <div class="panel-body">
          <div class="meta-list">{''.join(meta_blocks)}</div>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head"><h2>Engagement Lanes</h2></div>
        <div class="panel-body">
          <div class="lane-grid">
            <div class="lane">
              <div class="eyebrow">Inputs</div>
              <div class="figure">{len(engagement["seeds"])}</div>
              <div class="tiny muted">Tracked seeds</div>
            </div>
            <div class="lane">
              <div class="eyebrow">Surface</div>
              <div class="figure">{int(counts.get('hosts', 0)) + int(counts.get('emails', 0))}</div>
              <div class="tiny muted">Hosts + emails</div>
            </div>
            <div class="lane">
              <div class="eyebrow">Signals</div>
              <div class="figure">{signal_count}</div>
              <div class="tiny muted">Severity-scored findings</div>
            </div>
            <div class="lane">
              <div class="eyebrow">Evidence</div>
              <div class="figure">{len(report_files) + len(graph_files) + len(audit_files)}</div>
              <div class="tiny muted">Artifacts linked here</div>
            </div>
          </div>
        </div>
      </section>

      <div class="route-grid">
        <section class="panel">
          <div class="panel-head"><h3>Route Inputs</h3></div>
          <div class="panel-body">
            <div class="route-card">
              <h3>Seeds</h3>
              {seed_html}
            </div>
            <div class="route-card" style="margin-top:14px">
              <h3>Scope</h3>
              {scope_html}
            </div>
          </div>
        </section>
        <section class="panel">
          <div class="panel-head"><h3>Executive Report</h3></div>
          <div class="panel-body">
            {report_callout_html}
          </div>
        </section>
        <section class="panel">
          <div class="panel-head"><h3>Maltego Workspace</h3></div>
          <div class="panel-body">
            {graph_stage_html}
            <p class="tiny muted" style="margin-top:14px">This route is reserved for the interactive graph view. Until the richer client lands, the page exposes the graph summary plus direct MTGX and GraphML artifact links.</p>
          </div>
        </section>
      </div>

      <section class="panel">
        <div class="panel-head"><h2>Artifacts</h2></div>
        <div class="panel-body">
          <div class="artifact-list">{artifact_block}</div>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head"><h2>Attack Graph</h2></div>
          <div class="panel-body">
            {graph_summary_html}
          <p class="tiny muted" style="margin-top:14px">MTGX is the native Maltego workspace artifact, while GraphML remains the lightweight import/export path. The page links above keep both visible instead of burying them in the report directory.</p>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head"><h2>Operational Timeline</h2></div>
        <div class="panel-body">
          {operational_timeline_html}
        </div>
      </section>

      <section class="panel">
        <div class="panel-head"><h2>Audit Timeline</h2></div>
        <div class="panel-body">
          {audit_timeline_html}
        </div>
      </section>

      {evidence_sections_html}

      {report_history_html}

      {report_previews_html}
    </div>
  </div>
</body>
</html>
"""


__all__ = [
    "DEFAULT_SEVERITY_ORDER",
    "ENGAGEMENT_SECTION_TITLES",
    "render_engagement_detail_page",
    "render_engagement_evidence_sections",
    "render_overview_page",
]
