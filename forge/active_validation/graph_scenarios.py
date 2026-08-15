from __future__ import annotations

import re
import sqlite3
from typing import Any, Mapping

from forge.graph.assets import list_asset_graph
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

_FORBIDDEN_KEY_FRAGMENTS = ("authorization", "credential", "password", "secret", "token")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def draft_active_validation_scenarios_from_asset_graph(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Draft safe active-validation jobs from graph-ranked exposure context."""
    row_limit = max(1, min(int(limit or 5), 25))
    graph = list_asset_graph(con, int(engagement_id), limit=max(row_limit * 4, 25))
    drafts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for path in graph.get("attack_paths", []) if isinstance(graph.get("attack_paths"), list) else []:
        if not isinstance(path, Mapping):
            continue
        exposure = path.get("exposure_summary")
        summary = exposure if isinstance(exposure, Mapping) else {}
        nodes = path.get("nodes") if isinstance(path.get("nodes"), list) else []
        for draft in _drafts_from_path(path, nodes, summary):
            _append_unique(drafts, seen, draft, row_limit)
            if len(drafts) >= row_limit:
                return drafts

    candidates = (
        graph.get("minimal_fix_set_candidates", [])
        if isinstance(graph.get("minimal_fix_set_candidates"), list)
        else []
    )
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        draft = _draft_from_fix_candidate(candidate)
        if draft:
            _append_unique(drafts, seen, draft, row_limit)
        if len(drafts) >= row_limit:
            return drafts

    critical_assets = graph.get("critical_assets", []) if isinstance(graph.get("critical_assets"), list) else []
    for asset in critical_assets:
        if not isinstance(asset, Mapping):
            continue
        draft = _draft_from_critical_asset(asset)
        if draft:
            _append_unique(drafts, seen, draft, row_limit)
        if len(drafts) >= row_limit:
            return drafts
    return drafts


def _drafts_from_path(
    path: Mapping[str, Any],
    nodes: list[Any],
    exposure_summary: Mapping[str, Any],
) -> list[dict[str, Any]]:
    drafts: list[dict[str, Any]] = []
    normalized_nodes = [node for node in nodes if isinstance(node, Mapping)]
    entry = normalized_nodes[0] if normalized_nodes else {}
    terminal = normalized_nodes[-1] if normalized_nodes else {}
    risk_tags = _string_list(exposure_summary.get("risk_tags"))
    reason = "validate_graph_ranked_attack_path"
    summary = str(exposure_summary.get("summary") or "").strip()
    path_id = str(path.get("path_id") or "").strip()

    entry_kind = _target_kind(entry)
    if entry_kind in {"host", "service", "asset"}:
        drafts.append(
            _scenario(
                target_ref=_entity_key(entry),
                target_kind=entry_kind,
                method="http_reachability",
                mode="dry_run",
                title="Plan safe reachability validation for graph entry point",
                reason=reason,
                risk_tags=risk_tags,
                expected_result="reachability_plan_only",
                graph_context={
                    "source": "asset_graph",
                    "path_id": path_id,
                    "terminal_entity_key": _safe_text(exposure_summary.get("terminal_entity_key")),
                    "summary": summary,
                },
            )
        )

    terminal_kind = _target_kind(terminal)
    if terminal_kind in {"cloud", "identity", "finding", "remediation"}:
        drafts.append(
            _scenario_for_node(
                terminal,
                reason=reason,
                risk_tags=risk_tags,
                path_id=path_id,
                summary=summary,
            )
        )
    return [draft for draft in drafts if draft]


def _draft_from_fix_candidate(candidate: Mapping[str, Any]) -> dict[str, Any]:
    reason = str(candidate.get("reason") or "validate_minimal_fix_candidate").strip()
    return _scenario_for_node(
        candidate,
        reason=reason,
        risk_tags=_string_list(candidate.get("risk_tags") or candidate.get("tags")),
        path_id="",
        summary=str(candidate.get("summary") or "").strip(),
    )


def _draft_from_critical_asset(asset: Mapping[str, Any]) -> dict[str, Any]:
    return _scenario_for_node(
        asset,
        reason="validate_critical_graph_asset",
        risk_tags=_string_list(asset.get("tags")),
        path_id="",
        summary="",
    )


def _scenario_for_node(
    node: Mapping[str, Any],
    *,
    reason: str,
    risk_tags: list[str],
    path_id: str,
    summary: str,
) -> dict[str, Any]:
    entity_kind = _target_kind(node)
    if entity_kind == "cloud":
        return _scenario(
            target_ref=_entity_key(node),
            target_kind="cloud",
            method="control_simulation",
            mode="lab",
            title="Simulate controls for graph-ranked cloud exposure",
            reason=reason,
            risk_tags=risk_tags,
            expected_result="expected_control_blocks_or_alerts",
            graph_context=_node_context(node, path_id=path_id, summary=summary),
        )
    if entity_kind == "identity":
        return _scenario(
            target_ref=_entity_key(node),
            target_kind="identity",
            method="control_simulation",
            mode="lab",
            title="Simulate least-privilege controls for graph-ranked identity",
            reason=reason,
            risk_tags=risk_tags,
            expected_result="expected_privilege_path_reduced_or_detected",
            graph_context=_node_context(node, path_id=path_id, summary=summary),
        )
    if entity_kind in {"finding", "remediation"}:
        return _scenario(
            target_ref=_entity_key(node),
            target_kind=entity_kind,
            method="fix_verification",
            mode="dry_run",
            title="Plan fix verification from graph-ranked remediation context",
            reason=reason,
            risk_tags=risk_tags,
            expected_result="fix_verification_plan_only",
            graph_context=_node_context(node, path_id=path_id, summary=summary),
        )
    if entity_kind in {"host", "service", "asset"}:
        return _scenario(
            target_ref=_entity_key(node),
            target_kind=entity_kind,
            method="http_reachability",
            mode="dry_run",
            title="Plan safe reachability validation for graph-ranked asset",
            reason=reason,
            risk_tags=risk_tags,
            expected_result="reachability_plan_only",
            graph_context=_node_context(node, path_id=path_id, summary=summary),
        )
    return {}


def _scenario(
    *,
    target_ref: str,
    target_kind: str,
    method: str,
    mode: str,
    title: str,
    reason: str,
    risk_tags: list[str],
    expected_result: str,
    graph_context: Mapping[str, Any],
) -> dict[str, Any]:
    safe_context = _scrub(graph_context)
    return {
        "title": title,
        "target_ref": _safe_text(target_ref),
        "target_kind": target_kind,
        "method": method,
        "mode": mode,
        "safe_profile": "non_destructive",
        "max_steps": 1,
        "approved": False,
        "approval_required": False,
        "network_execution": False,
        "expected_result": expected_result,
        "reason": _safe_text(reason),
        "risk_tags": [_safe_text(tag) for tag in risk_tags[:12]],
        "metadata": {
            "source": "asset_graph",
            "scenario_family": "graph_recommended_active_validation",
            "reason": _safe_text(reason),
            "expected_result": expected_result,
            "network_execution": False,
            "graph": safe_context if isinstance(safe_context, dict) else {},
        },
    }


def _append_unique(
    drafts: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    draft: dict[str, Any],
    limit: int,
) -> None:
    if not draft or len(drafts) >= limit:
        return
    key = (
        str(draft.get("target_ref") or ""),
        str(draft.get("method") or ""),
        str(draft.get("mode") or ""),
    )
    if not key[0] or key in seen:
        return
    seen.add(key)
    drafts.append(draft)


def _node_context(
    node: Mapping[str, Any],
    *,
    path_id: str,
    summary: str,
) -> dict[str, Any]:
    return {
        "source": "asset_graph",
        "path_id": _safe_text(path_id),
        "node_id": node.get("node_id"),
        "entity_key": _entity_key(node),
        "entity_type": _target_kind(node),
        "risk_score": node.get("risk_score"),
        "summary": summary,
    }


def _target_kind(node: Mapping[str, Any]) -> str:
    raw = str(node.get("entity_type") or node.get("target_kind") or "asset").strip().lower()
    if raw in {"cloud", "identity", "finding", "remediation", "host", "service"}:
        return raw
    return "asset"


def _entity_key(node: Mapping[str, Any]) -> str:
    return _safe_text(node.get("entity_key") or node.get("target_ref") or node.get("label") or "")


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = _safe_text(item)
        if text and text not in result:
            result.append(text)
    return result


def _safe_text(value: object) -> str:
    text = str(value or "").strip()
    return _URL_RE.sub(lambda match: strip_sensitive_url_query(match.group(0)), text)


def _scrub(value: Any) -> Any:
    if isinstance(value, Mapping):
        clean: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if any(fragment in lowered for fragment in _FORBIDDEN_KEY_FRAGMENTS):
                continue
            clean[key] = _scrub(raw_value)
        return clean
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)
