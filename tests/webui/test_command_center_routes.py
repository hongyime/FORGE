from datetime import datetime, timezone
from typing import Any

import pytest

from forge.models.pydantic_models import CommandEvent
from forge.webui.command_center_routes import (
    CommandCenterRouteError,
    approve_action_payload,
    approve_action_route_payload,
    command_body_engagement_id,
    command_context_from_body,
    emergency_stop_payload,
    emergency_stop_route_payload,
    execute_action_payload,
    execute_action_route_payload,
    host_actions_payload,
    host_actions_route_payload,
    host_context_payload,
    host_context_route_payload,
    progress_event_for_command_event,
    publish_command_progress_event,
    timeline_payload,
    timeline_route_payload,
    toggle_sentry_payload,
    toggle_sentry_route_payload,
)


class _FakeCommandCenter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def get_host_context(self, host: str) -> dict[str, Any]:
        self.calls.append(("get_host_context", (host,), {}))
        return {"host": host}

    def list_host_actions(self, host: str) -> list[dict[str, Any]]:
        self.calls.append(("list_host_actions", (host,), {}))
        return [{"action_id": "action-1"}]

    def execute_action(self, action_id: str, context: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("execute_action", (action_id,), {"context": context}))
        return {"status": "queued", "action": {"action_id": action_id}}

    def approve_action(self, action_id: str, context: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("approve_action", (action_id,), {"context": context}))
        return {"status": "approved", "action": {"action_id": action_id}}

    def toggle_sentry(self, enabled: bool) -> dict[str, Any]:
        self.calls.append(("toggle_sentry", (enabled,), {}))
        return {"status": "updated", "state": {"enabled": enabled}}

    def emergency_stop(self) -> dict[str, Any]:
        self.calls.append(("emergency_stop", (), {}))
        return {"status": "emergency_stop"}

    def list_timeline(self) -> list[dict[str, Any]]:
        self.calls.append(("list_timeline", (), {}))
        return [{"event_type": "asset_discovered"}]


class _FailingCommandCenter(_FakeCommandCenter):
    def execute_action(self, action_id: str, context: dict[str, Any]) -> dict[str, Any]:
        raise ValueError(f"cannot execute {action_id}")

    def approve_action(self, action_id: str, context: dict[str, Any]) -> dict[str, Any]:
        raise ValueError(f"cannot approve {action_id}")


def test_command_body_engagement_id_preserves_missing_body_contract() -> None:
    assert command_body_engagement_id({"engagement_id": 1001}) == 1001
    assert command_body_engagement_id({"engagement_id": "1001"}) == "1001"
    with pytest.raises(CommandCenterRouteError, match="engagement_id required"):
        command_body_engagement_id({})
    with pytest.raises(CommandCenterRouteError, match="engagement_id required"):
        command_body_engagement_id({"engagement_id": 0})


def test_command_context_from_body_inherits_only_roe_scope_fields() -> None:
    scope_manifest = {"roe_id": "ROE-WEB-2026-07", "domains": ["app.acme.example"]}

    context = command_context_from_body(
        {
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest": scope_manifest,
            "require_scope_manifest": True,
            "context": {"roe_id": "ROE-OVERRIDE", "extra": "ignored"},
        }
    )

    assert context == {
        "roe_id": "ROE-OVERRIDE",
        "scope_manifest": scope_manifest,
        "require_scope_manifest": True,
    }


def test_host_action_sentry_and_timeline_payloads_call_service_methods() -> None:
    service = _FakeCommandCenter()

    assert host_context_payload(service, "app.acme.example") == {"host": "app.acme.example"}
    assert host_actions_payload(service, "app.acme.example") == {
        "actions": [{"action_id": "action-1"}]
    }
    assert toggle_sentry_payload(service, {"enabled": True}) == {
        "status": "updated",
        "state": {"enabled": True},
    }
    assert toggle_sentry_payload(service, {}) == {
        "status": "updated",
        "state": {"enabled": False},
    }
    assert emergency_stop_payload(service) == {"status": "emergency_stop"}
    assert timeline_payload(service) == {"events": [{"event_type": "asset_discovered"}]}

    assert [call[0] for call in service.calls] == [
        "get_host_context",
        "list_host_actions",
        "toggle_sentry",
        "toggle_sentry",
        "emergency_stop",
        "list_timeline",
    ]


def test_command_center_route_payload_wrappers_delegate_to_service_methods() -> None:
    service = _FakeCommandCenter()

    assert host_context_route_payload(service, "app.acme.example") == {
        "host": "app.acme.example"
    }
    assert host_actions_route_payload(service, "app.acme.example") == {
        "actions": [{"action_id": "action-1"}]
    }
    assert execute_action_route_payload(service, "action-1", {})["status"] == "queued"
    assert approve_action_route_payload(service, "action-1", {})["status"] == "approved"
    assert toggle_sentry_route_payload(service, {"enabled": True})["state"]["enabled"] is True
    assert emergency_stop_route_payload(service) == {"status": "emergency_stop"}
    assert timeline_route_payload(service) == {"events": [{"event_type": "asset_discovered"}]}

    assert [call[0] for call in service.calls] == [
        "get_host_context",
        "list_host_actions",
        "execute_action",
        "approve_action",
        "toggle_sentry",
        "emergency_stop",
        "list_timeline",
    ]


def test_action_payload_helpers_pass_inherited_context_and_wrap_value_errors() -> None:
    service = _FakeCommandCenter()
    body = {
        "roe_id": "ROE-WEB-2026-07",
        "scope_manifest": {"domains": ["app.acme.example"]},
    }

    assert execute_action_payload(service, "action-1", body)["status"] == "queued"
    assert approve_action_payload(service, "action-1", body)["status"] == "approved"
    assert service.calls == [
        (
            "execute_action",
            ("action-1",),
            {
                "context": {
                    "roe_id": "ROE-WEB-2026-07",
                    "scope_manifest": {"domains": ["app.acme.example"]},
                }
            },
        ),
        (
            "approve_action",
            ("action-1",),
            {
                "context": {
                    "roe_id": "ROE-WEB-2026-07",
                    "scope_manifest": {"domains": ["app.acme.example"]},
                }
            },
        ),
    ]

    failing = _FailingCommandCenter()
    with pytest.raises(CommandCenterRouteError, match="cannot execute action-2"):
        execute_action_payload(failing, "action-2", {})
    with pytest.raises(CommandCenterRouteError, match="cannot approve action-2"):
        approve_action_payload(failing, "action-2", {})


def test_command_event_helpers_preserve_progress_event_contract() -> None:
    event = CommandEvent(
        event_id="evt-1",
        event_type="action_queued",
        engagement_id=1001,
        timestamp=datetime(2026, 8, 13, tzinfo=timezone.utc),
        payload={"action_id": "action-1"},
        severity="info",
    )

    progress = progress_event_for_command_event(event)
    published: list[Any] = []
    publish_command_progress_event(published.append, event)

    assert progress.engagement_id == 1001
    assert progress.message == "action_queued"
    assert progress.payload == {"action_id": "action-1"}
    assert published == [progress]
