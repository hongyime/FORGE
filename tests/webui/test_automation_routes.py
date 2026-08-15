from pathlib import Path
from typing import Any

import pytest

from forge.distributed.scheduler import ScheduledTask
from forge.webui import automation_routes as routes
from forge.webui.automation_routes import (
    AutomationRouteError,
    automation_playbook_route_payload,
    automation_suggestions_route_payload,
    execute_automation_route_payload,
    parse_automation_action_request,
    parse_automation_playbook_request,
    queue_automation_action,
    run_automation_playbook,
)


class _FakeScheduler:
    scheduled: list[ScheduledTask] = []

    def __init__(
        self,
        *,
        db_path: Path,
        queue: Any,
        event_publisher: Any,
    ) -> None:
        self.db_path = db_path
        self.queue = queue
        self.event_publisher = event_publisher

    def schedule(self, task: ScheduledTask) -> None:
        self.scheduled.append(task)


def test_parse_automation_action_request_preserves_validation_contract() -> None:
    with pytest.raises(AutomationRouteError, match="engagement_id and action"):
        parse_automation_action_request({"engagement_id": 1001})
    with pytest.raises(AutomationRouteError, match="params must be an object"):
        parse_automation_action_request(
            {"engagement_id": 1001, "action": "recon:crawl", "params": []}
        )

    request = parse_automation_action_request(
        {"engagement_id": 1001, "action": " recon:crawl ", "params": {"target": "x"}}
    )

    assert request.engagement_id == 1001
    assert request.action == "recon:crawl"
    assert request.params == {"target": "x"}


def test_automation_suggestions_route_payload_delegates_to_engine(monkeypatch) -> None:
    monkeypatch.setattr(
        routes,
        "automation_suggestions_payload",
        lambda engagement_id: {"items": [{"engagement_id": engagement_id}]},
    )

    assert automation_suggestions_route_payload(1001) == {
        "items": [{"engagement_id": 1001}]
    }


def test_queue_automation_action_inherits_scope_context_and_schedules(monkeypatch) -> None:
    _FakeScheduler.scheduled = []
    monkeypatch.setattr(routes, "TaskScheduler", _FakeScheduler)
    scope_manifest = {"roe_id": "ROE-WEB-2026-07", "domains": ["app.acme.example"]}
    request = parse_automation_action_request(
        {
            "engagement_id": 1001,
            "action": "recon:crawl",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest": scope_manifest,
            "params": {"target": "https://app.acme.example", "depth": 2},
        }
    )

    payload = queue_automation_action(
        request,
        db_path=Path("engagement.db"),
        queue=object(),
        event_publisher=None,
    )

    assert payload == {"status": "queued", "task_key": "crawl:https://app.acme.example"}
    assert len(_FakeScheduler.scheduled) == 1
    task = _FakeScheduler.scheduled[0]
    assert task.engagement_id == 1001
    assert task.task_key == "crawl:https://app.acme.example"
    assert task.payload["task_type"] == "crawl"
    assert task.payload["depth"] == 2
    assert task.payload["roe_id"] == "ROE-WEB-2026-07"
    assert task.payload["scope_manifest"] == scope_manifest


def test_execute_automation_route_payload_delegates_to_queue(monkeypatch) -> None:
    _FakeScheduler.scheduled = []
    monkeypatch.setattr(routes, "TaskScheduler", _FakeScheduler)
    scope_manifest = {"roe_id": "ROE-WEB-2026-07", "domains": ["app.acme.example"]}
    request = parse_automation_action_request(
        {
            "engagement_id": 1001,
            "action": "recon:crawl",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest": scope_manifest,
            "params": {"target": "https://app.acme.example"},
        }
    )

    payload = execute_automation_route_payload(
        request,
        db_path=Path("engagement.db"),
        queue=object(),
        event_publisher=None,
    )

    assert payload == {"status": "queued", "task_key": "crawl:https://app.acme.example"}
    assert len(_FakeScheduler.scheduled) == 1


def test_queue_automation_action_audits_scope_denial_before_scheduling(monkeypatch) -> None:
    _FakeScheduler.scheduled = []
    monkeypatch.setattr(routes, "TaskScheduler", _FakeScheduler)
    denials: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        routes,
        "audit_automation_scope_denial",
        lambda *args: denials.append(args),
    )
    request = parse_automation_action_request(
        {
            "engagement_id": 1001,
            "action": "recon:crawl",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest": {
                "roe_id": "ROE-WEB-2026-07",
                "domains": ["app.acme.example"],
                "urls": ["https://app.acme.example/app/"],
            },
            "params": {"target": "https://app.acme.example/admin"},
        }
    )

    with pytest.raises(AutomationRouteError, match="scope_manifest_denied"):
        queue_automation_action(
            request,
            db_path=Path("engagement.db"),
            queue=object(),
            event_publisher=None,
        )

    assert _FakeScheduler.scheduled == []
    assert denials == [
        (
            Path("engagement.db"),
            1001,
            "crawl",
            "https://app.acme.example/admin",
            "scope_manifest_denied",
        )
    ]


def test_parse_automation_playbook_request_preserves_validation_contract() -> None:
    with pytest.raises(AutomationRouteError, match="engagement_id, playbook, and target"):
        parse_automation_playbook_request({"engagement_id": 1001, "playbook": "recon_full"})
    with pytest.raises(AutomationRouteError, match="Unknown playbook"):
        parse_automation_playbook_request(
            {"engagement_id": 1001, "playbook": "unknown", "target": "acme.example"}
        )

    request = parse_automation_playbook_request(
        {"engagement_id": 1001, "playbook": "recon_full", "target": "acme.example"}
    )

    assert request.engagement_id == 1001
    assert request.playbook == "recon_full"
    assert request.target == "acme.example"


def test_run_automation_playbook_inherits_scope_context(monkeypatch) -> None:
    _FakeScheduler.scheduled = []
    monkeypatch.setattr(routes, "TaskScheduler", _FakeScheduler)

    class FakePlaybookEngine:
        calls: list[tuple[str, Any, Any, dict[str, Any]]] = []

        def __init__(self, scheduler: Any) -> None:
            self.scheduler = scheduler

        def run_recon_full(
            self,
            engagement_id: Any,
            target: Any,
            *,
            context: dict[str, Any],
        ) -> None:
            self.calls.append(("recon_full", engagement_id, target, context))

        def run_vuln_discovery(
            self,
            engagement_id: Any,
            target: Any,
            *,
            context: dict[str, Any],
        ) -> None:
            self.calls.append(("vuln_discovery", engagement_id, target, context))

    FakePlaybookEngine.calls = []
    monkeypatch.setattr(routes, "PlaybookEngine", FakePlaybookEngine)
    scope_manifest = {"roe_id": "ROE-WEB-2026-07", "domains": ["acme.example"]}
    request = parse_automation_playbook_request(
        {
            "engagement_id": 1001,
            "playbook": "recon_full",
            "target": "acme.example",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest": scope_manifest,
        }
    )

    payload = run_automation_playbook(
        request,
        db_path=Path("engagement.db"),
        queue=object(),
        event_publisher=None,
    )

    assert payload == {"status": "playbook_started"}
    assert FakePlaybookEngine.calls == [
        (
            "recon_full",
            1001,
            "acme.example",
            {"roe_id": "ROE-WEB-2026-07", "scope_manifest": scope_manifest},
        )
    ]


def test_automation_playbook_route_payload_delegates_to_playbook_runner(
    monkeypatch,
) -> None:
    _FakeScheduler.scheduled = []
    monkeypatch.setattr(routes, "TaskScheduler", _FakeScheduler)

    class FakePlaybookEngine:
        calls: list[tuple[str, Any, Any, dict[str, Any]]] = []

        def __init__(self, scheduler: Any) -> None:
            self.scheduler = scheduler

        def run_recon_full(
            self,
            engagement_id: Any,
            target: Any,
            *,
            context: dict[str, Any],
        ) -> None:
            self.calls.append(("recon_full", engagement_id, target, context))

        def run_vuln_discovery(
            self,
            engagement_id: Any,
            target: Any,
            *,
            context: dict[str, Any],
        ) -> None:
            self.calls.append(("vuln_discovery", engagement_id, target, context))

    FakePlaybookEngine.calls = []
    monkeypatch.setattr(routes, "PlaybookEngine", FakePlaybookEngine)
    scope_manifest = {"roe_id": "ROE-WEB-2026-07", "domains": ["acme.example"]}
    request = parse_automation_playbook_request(
        {
            "engagement_id": 1001,
            "playbook": "recon_full",
            "target": "acme.example",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest": scope_manifest,
        }
    )

    payload = automation_playbook_route_payload(
        request,
        db_path=Path("engagement.db"),
        queue=object(),
        event_publisher=None,
    )

    assert payload == {"status": "playbook_started"}
    assert FakePlaybookEngine.calls == [
        (
            "recon_full",
            1001,
            "acme.example",
            {"roe_id": "ROE-WEB-2026-07", "scope_manifest": scope_manifest},
        )
    ]
