"""Web UI command-center route helpers."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from forge.config import ForgeConfig
from forge.distributed.coordinator import QueueCoordinator
from forge.models.pydantic_models import CommandEvent
from forge.utils.playbooks import ROE_SCOPE_CONTEXT_KEYS, inherit_roe_scope_context
from forge.webui.command_center import CommandCenterService
from forge.webui.state import ProgressEvent


class CommandCenterRouteError(ValueError):
    """Request validation or command-center failure that should map to HTTP 400."""


PublishCommandProgress = Callable[[ProgressEvent], None]
PublishCommandEvent = Callable[[CommandEvent], None]


def command_center_service(
    engagement_id: Any,
    *,
    config: ForgeConfig,
    coordinator: QueueCoordinator,
    publish_event: PublishCommandEvent,
) -> CommandCenterService:
    return CommandCenterService(
        engagement_id=engagement_id,
        config=config,
        coordinator=coordinator,
        publish_event=publish_event,
    )


def progress_event_for_command_event(event: CommandEvent) -> ProgressEvent:
    return ProgressEvent(
        engagement_id=event.engagement_id,
        message=event.event_type,
        payload=event.payload,
    )


def publish_command_progress_event(
    publish_sync: PublishCommandProgress,
    event: CommandEvent,
) -> None:
    publish_sync(progress_event_for_command_event(event))


def build_command_event_publisher(
    publish_sync: PublishCommandProgress,
) -> PublishCommandEvent:
    def publish_event(event: CommandEvent) -> None:
        publish_command_progress_event(publish_sync, event)

    return publish_event


def command_body_engagement_id(body: dict[str, Any]) -> Any:
    engagement_id = body.get("engagement_id")
    if not engagement_id:
        raise CommandCenterRouteError("engagement_id required in body")
    return engagement_id


def build_command_body_engagement_id_parser(
    *,
    http_exception: type[Exception],
) -> Callable[[dict[str, Any]], Any]:
    def parse_engagement_id(body: dict[str, Any]) -> Any:
        try:
            return command_body_engagement_id(body)
        except CommandCenterRouteError as exc:
            raise http_exception(status_code=400, detail=str(exc)) from exc

    return parse_engagement_id


def command_context_from_body(body: dict[str, Any]) -> dict[str, Any]:
    context = body.get("context") if isinstance(body.get("context"), dict) else {}
    return inherit_roe_scope_context(
        body,
        {key: context[key] for key in ROE_SCOPE_CONTEXT_KEYS if key in context},
    )


def host_context_payload(service: CommandCenterService, host: str) -> dict[str, Any]:
    return service.get_host_context(host)


def host_context_route_payload(service: CommandCenterService, host: str) -> dict[str, Any]:
    return host_context_payload(service, host)


def host_actions_payload(service: CommandCenterService, host: str) -> dict[str, Any]:
    return {"actions": service.list_host_actions(host)}


def host_actions_route_payload(service: CommandCenterService, host: str) -> dict[str, Any]:
    return host_actions_payload(service, host)


def execute_action_payload(
    service: CommandCenterService,
    action_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    try:
        return service.execute_action(action_id, context=command_context_from_body(body))
    except ValueError as exc:
        raise CommandCenterRouteError(str(exc)) from exc


def execute_action_route_payload(
    service: CommandCenterService,
    action_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    return execute_action_payload(service, action_id, body)


def approve_action_payload(
    service: CommandCenterService,
    action_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    try:
        return service.approve_action(action_id, context=command_context_from_body(body))
    except ValueError as exc:
        raise CommandCenterRouteError(str(exc)) from exc


def approve_action_route_payload(
    service: CommandCenterService,
    action_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    return approve_action_payload(service, action_id, body)


def toggle_sentry_payload(
    service: CommandCenterService,
    body: dict[str, Any],
) -> dict[str, Any]:
    return service.toggle_sentry(body.get("enabled", False))


def toggle_sentry_route_payload(
    service: CommandCenterService,
    body: dict[str, Any],
) -> dict[str, Any]:
    return toggle_sentry_payload(service, body)


def emergency_stop_payload(service: CommandCenterService) -> dict[str, Any]:
    return service.emergency_stop()


def emergency_stop_route_payload(service: CommandCenterService) -> dict[str, Any]:
    return emergency_stop_payload(service)


def timeline_payload(service: CommandCenterService) -> dict[str, Any]:
    return {"events": service.list_timeline()}


def timeline_route_payload(service: CommandCenterService) -> dict[str, Any]:
    return timeline_payload(service)


__all__ = [
    "CommandCenterRouteError",
    "approve_action_payload",
    "approve_action_route_payload",
    "build_command_body_engagement_id_parser",
    "build_command_event_publisher",
    "command_body_engagement_id",
    "command_center_service",
    "command_context_from_body",
    "emergency_stop_payload",
    "emergency_stop_route_payload",
    "execute_action_payload",
    "execute_action_route_payload",
    "host_actions_payload",
    "host_actions_route_payload",
    "host_context_payload",
    "host_context_route_payload",
    "progress_event_for_command_event",
    "publish_command_progress_event",
    "timeline_payload",
    "timeline_route_payload",
    "toggle_sentry_payload",
    "toggle_sentry_route_payload",
]
