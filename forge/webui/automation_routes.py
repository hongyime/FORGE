"""Web UI automation route helpers."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forge.distributed.scheduler import ScheduledTask, TaskScheduler
from forge.utils.automation import AutomationEngine, EXECUTABLE_AUTOMATION_ACTIONS
from forge.utils.playbooks import (
    PlaybookAuthorizationError,
    PlaybookEngine,
    ROE_SCOPE_CONTEXT_KEYS,
    inherit_roe_scope_context,
    require_roe_scope_context,
)
from forge.webui.automation_scope import (
    AutomationScopeError,
    assert_automation_target_in_scope,
    audit_automation_scope_denial,
)


ProgressPublisher = Callable[[int, str, dict[str, Any]], None]


class AutomationRouteError(ValueError):
    """Request validation or scope failure that should map to HTTP 400."""


@dataclass(frozen=True)
class AutomationActionRequest:
    body: dict[str, Any]
    engagement_id: Any
    action: str
    params: dict[str, Any]


@dataclass(frozen=True)
class AutomationPlaybookRequest:
    body: dict[str, Any]
    engagement_id: Any
    playbook: Any
    target: Any


def automation_suggestions_payload(
    engagement_id: int,
    *,
    engine_factory: Callable[[int], Any] = AutomationEngine,
) -> dict[str, Any]:
    engine = engine_factory(engagement_id)
    suggestions = engine.get_suggestions()
    return {"items": [suggestion.__dict__ for suggestion in suggestions]}


def automation_suggestions_route_payload(engagement_id: int) -> dict[str, Any]:
    return automation_suggestions_payload(engagement_id)


def parse_automation_action_request(body: dict[str, Any]) -> AutomationActionRequest:
    engagement_id = body.get("engagement_id")
    action = str(body.get("action") or "").strip()
    params = body.get("params", {})

    if not engagement_id or not action:
        raise AutomationRouteError("engagement_id and action are required.")
    if not isinstance(params, dict):
        raise AutomationRouteError("params must be an object.")
    return AutomationActionRequest(
        body=body,
        engagement_id=engagement_id,
        action=action,
        params=params,
    )


def queue_automation_action(
    request: AutomationActionRequest,
    *,
    db_path: Path,
    queue: Any,
    event_publisher: ProgressPublisher | None,
) -> dict[str, str]:
    task_type = EXECUTABLE_AUTOMATION_ACTIONS.get(request.action)
    if task_type is None:
        raise AutomationRouteError("Unsupported automation action.")

    target = str(request.params.get("target") or "").strip()
    if not target:
        raise AutomationRouteError("target is required for automation action.")

    scheduler = TaskScheduler(
        db_path=db_path,
        queue=queue,
        event_publisher=event_publisher,
    )

    task_key = f"{task_type}:{target}"
    payload = inherit_roe_scope_context(
        request.body,
        {"task_type": task_type, **request.params},
    )
    try:
        require_roe_scope_context(payload)
        assert_automation_target_in_scope(payload, target)
    except PlaybookAuthorizationError as exc:
        raise AutomationRouteError(str(exc)) from exc
    except AutomationScopeError as exc:
        audit_automation_scope_denial(
            db_path,
            int(request.engagement_id),
            task_type,
            target,
            exc.reason,
        )
        raise AutomationRouteError(exc.reason) from exc

    scheduler.schedule(
        ScheduledTask(
            engagement_id=request.engagement_id,
            task_key=task_key,
            payload=payload,
        )
    )

    return {"status": "queued", "task_key": task_key}


def execute_automation_route_payload(
    request: AutomationActionRequest,
    *,
    db_path: Path,
    queue: Any,
    event_publisher: ProgressPublisher | None,
) -> dict[str, str]:
    return queue_automation_action(
        request,
        db_path=db_path,
        queue=queue,
        event_publisher=event_publisher,
    )


def parse_automation_playbook_request(body: dict[str, Any]) -> AutomationPlaybookRequest:
    engagement_id = body.get("engagement_id")
    playbook = body.get("playbook")
    target = body.get("target")

    if not engagement_id or not playbook or not target:
        raise AutomationRouteError("engagement_id, playbook, and target are required.")
    if playbook not in {"recon_full", "vuln_discovery"}:
        raise AutomationRouteError(f"Unknown playbook: {playbook}")
    return AutomationPlaybookRequest(
        body=body,
        engagement_id=engagement_id,
        playbook=playbook,
        target=target,
    )


def run_automation_playbook(
    request: AutomationPlaybookRequest,
    *,
    db_path: Path,
    queue: Any,
    event_publisher: ProgressPublisher | None,
) -> dict[str, str]:
    scheduler = TaskScheduler(
        db_path=db_path,
        queue=queue,
        event_publisher=event_publisher,
    )
    engine = PlaybookEngine(scheduler)
    context = request.body.get("context") if isinstance(request.body.get("context"), dict) else {}
    context = inherit_roe_scope_context(
        request.body,
        {key: context[key] for key in ROE_SCOPE_CONTEXT_KEYS if key in context},
    )
    playbook_task_type = "crawl" if request.playbook == "vuln_discovery" else "subdomains"

    try:
        require_roe_scope_context(context)
        assert_automation_target_in_scope(context, str(request.target))
        if request.playbook == "recon_full":
            engine.run_recon_full(request.engagement_id, request.target, context=context)
        elif request.playbook == "vuln_discovery":
            engine.run_vuln_discovery(request.engagement_id, request.target, context=context)
    except PlaybookAuthorizationError as exc:
        raise AutomationRouteError(str(exc)) from exc
    except AutomationScopeError as exc:
        audit_automation_scope_denial(
            db_path,
            int(request.engagement_id),
            playbook_task_type,
            str(request.target),
            exc.reason,
        )
        raise AutomationRouteError(exc.reason) from exc

    return {"status": "playbook_started"}


def automation_playbook_route_payload(
    request: AutomationPlaybookRequest,
    *,
    db_path: Path,
    queue: Any,
    event_publisher: ProgressPublisher | None,
) -> dict[str, str]:
    return run_automation_playbook(
        request,
        db_path=db_path,
        queue=queue,
        event_publisher=event_publisher,
    )


__all__ = [
    "AutomationActionRequest",
    "AutomationPlaybookRequest",
    "AutomationRouteError",
    "automation_playbook_route_payload",
    "automation_suggestions_payload",
    "automation_suggestions_route_payload",
    "execute_automation_route_payload",
    "parse_automation_action_request",
    "parse_automation_playbook_request",
    "queue_automation_action",
    "run_automation_playbook",
]
