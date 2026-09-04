"""Tests for forge.plugins.event_bus (E2.2)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from forge.plugins.event_bus import (
    MAX_PAYLOAD_BYTES,
    PluginEvent,
    PluginEventAuditError,
    PluginEventBindingError,
    PluginEventBus,
    PluginEventDisabledError,
    PluginEventRateLimitError,
    PluginEventValidationError,
)


def _valid_artifact_payload(artifact_id: int = 1) -> dict:
    """Build a payload that satisfies ArtifactDiscoveredSchema."""
    return {
        "artifact_id": artifact_id,
        "artifact_type": "host",
        "source": "test",
        "discovered_at": "2026-01-01T00:00:00Z",
    }


def _mk_event(
    *,
    engagement_id: int = 1,
    plugin_id: str = "plug-a",
    event_type: str = "artifact:discovered",
    payload: dict | None = None,
    timestamp: datetime | None = None,
    artifact_id: int = 1,
) -> PluginEvent:
    return PluginEvent(
        event_type=event_type,
        engagement_id=engagement_id,
        plugin_id=plugin_id,
        payload=payload if payload is not None else _valid_artifact_payload(artifact_id),
        **({"timestamp": timestamp} if timestamp else {}),
    )


@pytest.fixture(autouse=True)
def _isolated_audit_path(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(
        "FORGE_PLUGIN_EVENT_AUDIT_PATH", str(tmp_path / "plugin-events.jsonl")
    )


@pytest.mark.asyncio
async def test_subscribe_publish_same_engagement() -> None:
    bus = PluginEventBus()
    received: list[PluginEvent] = []

    async def cb(e: PluginEvent) -> None:
        received.append(e)

    await bus.register_publisher(1, "sub-a")
    await bus.register_publisher(1, "plug-a")
    await bus.subscribe(1, "sub-a", cb)
    delivered = await bus.publish(_mk_event(engagement_id=1))
    assert delivered == 1
    assert len(received) == 1
    assert received[0].event_type == "artifact:discovered"


@pytest.mark.asyncio
async def test_delivery_to_multiple_subscribers() -> None:
    bus = PluginEventBus()
    hits_a: list[PluginEvent] = []
    hits_b: list[PluginEvent] = []

    async def async_cb(e: PluginEvent) -> None:
        hits_b.append(e)

    for plugin_id in ("plug-a", "sub-a", "sub-b"):
        await bus.register_publisher(7, plugin_id)
    await bus.subscribe(7, "sub-a", lambda e: hits_a.append(e))
    await bus.subscribe(7, "sub-b", async_cb)
    delivered = await bus.publish(_mk_event(engagement_id=7))
    assert delivered == 2
    assert len(hits_a) == 1
    assert len(hits_b) == 1


@pytest.mark.asyncio
async def test_engagement_isolation() -> None:
    bus = PluginEventBus()
    hits: list[PluginEvent] = []

    await bus.register_publisher(1, "subscriber")
    await bus.register_publisher(2, "plug-a")
    await bus.subscribe(1, "subscriber", lambda e: hits.append(e))
    delivered = await bus.publish(_mk_event(engagement_id=2))
    assert delivered == 0
    assert hits == []

    events_e1 = await bus.get_events(1, datetime(2000, 1, 1, tzinfo=UTC))
    events_e2 = await bus.get_events(2, datetime(2000, 1, 1, tzinfo=UTC))
    assert events_e1 == []
    assert len(events_e2) == 1


@pytest.mark.asyncio
async def test_unsubscribe() -> None:
    bus = PluginEventBus()
    hits: list[PluginEvent] = []
    await bus.register_publisher(1, "subscriber")
    await bus.register_publisher(1, "plug-a")
    await bus.subscribe(1, "subscriber", lambda e: hits.append(e))
    assert await bus.unsubscribe(1, "subscriber") is True
    assert await bus.unsubscribe(1, "subscriber") is False
    delivered = await bus.publish(_mk_event(engagement_id=1))
    assert delivered == 0
    assert hits == []


@pytest.mark.asyncio
async def test_forbidden_field_rejected_at_construction() -> None:
    with pytest.raises(Exception):
        PluginEvent(
            event_type="artifact:discovered",
            engagement_id=1,
            plugin_id="plug",
            payload={"password": "leak"},
        )


@pytest.mark.asyncio
async def test_forbidden_field_nested_rejected() -> None:
    with pytest.raises(Exception):
        PluginEvent(
            event_type="artifact:discovered",
            engagement_id=1,
            plugin_id="plug",
            payload={"nested": {"api_key": "AKIA..."}},
        )


@pytest.mark.asyncio
async def test_forbidden_field_in_list_rejected() -> None:
    with pytest.raises(Exception):
        PluginEvent(
            event_type="artifact:discovered",
            engagement_id=1,
            plugin_id="plug",
            payload={"creds": [{"token": "abc"}]},
        )


@pytest.mark.asyncio
async def test_payload_size_limit() -> None:
    big = {"blob": "x" * (MAX_PAYLOAD_BYTES + 1)}
    with pytest.raises(Exception):
        PluginEvent(
            event_type="artifact:discovered",
            engagement_id=1,
            plugin_id="plug",
            payload=big,
        )


@pytest.mark.asyncio
async def test_unknown_event_type_rejected() -> None:
    with pytest.raises(Exception):
        PluginEvent(
            event_type="malicious:type",
            engagement_id=1,
            plugin_id="plug",
            payload={},
        )


@pytest.mark.asyncio
async def test_rate_limit_enforced() -> None:
    bus = PluginEventBus(max_events_per_minute=5, max_events_per_burst=5)
    await bus.register_publisher(42, "plug-a")
    for _ in range(5):
        await bus.publish(_mk_event(engagement_id=42))
    with pytest.raises(PluginEventRateLimitError):
        await bus.publish(_mk_event(engagement_id=42))


@pytest.mark.asyncio
async def test_rate_limit_is_global_per_plugin() -> None:
    bus = PluginEventBus(max_events_per_minute=3, max_events_per_burst=10)
    await bus.register_publisher(1, "plug-a")
    await bus.register_publisher(2, "plug-a")
    await bus.publish(_mk_event(engagement_id=1))
    await bus.publish(_mk_event(engagement_id=1))
    await bus.publish(_mk_event(engagement_id=2))
    with pytest.raises(PluginEventRateLimitError):
        await bus.publish(_mk_event(engagement_id=2))


@pytest.mark.asyncio
async def test_event_ordering_fifo() -> None:
    bus = PluginEventBus()
    await bus.register_publisher(9, "plug-a")
    base = datetime.now(UTC) - timedelta(minutes=1)
    for i in range(10):
        await bus.publish(
            _mk_event(
                engagement_id=9,
                artifact_id=i + 1,
                timestamp=base + timedelta(seconds=i),
            )
        )
    events = await bus.get_events(9, datetime(2000, 1, 1, tzinfo=UTC))
    assert [e.payload["artifact_id"] for e in events] == list(range(1, 11))


@pytest.mark.asyncio
async def test_history_bounded_to_1000() -> None:
    bus = PluginEventBus(
        max_events_per_minute=10_000, max_events_per_burst=10_000
    )
    await bus.register_publisher(3, "plug-a")
    for i in range(1050):
        await bus.publish(_mk_event(engagement_id=3, artifact_id=i + 1))
    events = await bus.get_events(3, datetime(2000, 1, 1, tzinfo=UTC))
    assert len(events) == 1000
    # Oldest 50 were evicted; first surviving event has artifact_id 'a50'.
    assert events[0].payload["artifact_id"] == 51
    assert events[-1].payload["artifact_id"] == 1050


@pytest.mark.asyncio
async def test_get_events_since_filter() -> None:
    bus = PluginEventBus()
    await bus.register_publisher(1, "plug-a")
    now = datetime.now(UTC)
    for i in range(5):
        await bus.publish(
            _mk_event(
                engagement_id=1,
                artifact_id=i + 1,
                timestamp=now + timedelta(seconds=i),
            )
        )
    cutoff = now + timedelta(seconds=2)
    events = await bus.get_events(1, cutoff)
    assert [e.payload["artifact_id"] for e in events] == [4, 5]


@pytest.mark.asyncio
async def test_callback_exception_does_not_break_publish() -> None:
    bus = PluginEventBus()
    hits: list[PluginEvent] = []

    def bad(_e: PluginEvent) -> None:
        raise RuntimeError("boom")

    for plugin_id in ("plug-a", "bad-sub", "good-sub"):
        await bus.register_publisher(1, plugin_id)
    await bus.subscribe(1, "bad-sub", bad)
    await bus.subscribe(1, "good-sub", lambda e: hits.append(e))
    delivered = await bus.publish(_mk_event(engagement_id=1))
    # bad callback still counts as delivered attempt? Our impl: only counts non-raising.
    assert delivered == 1
    assert len(hits) == 1


@pytest.mark.asyncio
async def test_publish_rejects_non_event() -> None:
    bus = PluginEventBus()
    with pytest.raises(PluginEventValidationError):
        await bus.publish("not-an-event")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_concurrent_publish_thread_safe() -> None:
    bus = PluginEventBus(
        max_events_per_minute=10_000, max_events_per_burst=10_000
    )
    await bus.register_publisher(1, "plug-a")
    await bus.register_publisher(2, "plug-a")

    async def worker(eid: int, n: int) -> None:
        for i in range(n):
            await bus.publish(
                _mk_event(engagement_id=eid, artifact_id=eid * 1000 + i + 1)
            )

    await asyncio.gather(worker(1, 50), worker(2, 50), worker(1, 50))
    e1 = await bus.get_events(1, datetime(2000, 1, 1, tzinfo=UTC))
    e2 = await bus.get_events(2, datetime(2000, 1, 1, tzinfo=UTC))
    assert len(e1) == 100
    assert len(e2) == 50


# ---------------------------------------------------------------------------
# Schema enforcement, per-plugin rate limit, engagement binding
# (spec §5.2 / §5.3 / §5.4 — CODEX ISSUE 4)
# ---------------------------------------------------------------------------


def _read_audit_lines(path) -> list[dict]:
    import json as _json
    from pathlib import Path as _Path
    p = _Path(path)
    if not p.exists():
        return []
    return [_json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line]


@pytest.mark.asyncio
async def test_publish_rejects_invalid_schema_and_audits(tmp_path, monkeypatch) -> None:
    """artifact:discovered with {foo: bar} must be rejected by the middleware
    and durably audited (spec §3 + §5.4)."""
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("FORGE_PLUGIN_EVENT_AUDIT_PATH", str(audit))
    bus = PluginEventBus()
    # Construct with a schema-invalid but forbidden-clean payload. PluginEvent's
    # own validators (forbidden/size) let it through; the middleware inside
    # publish() must catch it.
    event = PluginEvent(
        event_type="artifact:discovered",
        engagement_id=1,
        plugin_id="plug-bad",
        payload={"foo": "bar"},
    )
    with pytest.raises(PluginEventValidationError):
        await bus.publish(event)
    records = _read_audit_lines(audit)
    matching = [
        r for r in records
        if r["outcome"] == "rejected"
        and r["plugin_id"] == "plug-bad"
        and r["engagement_id"] == 1
        and r["event_type"] == "artifact:discovered"
    ]
    assert matching, f"expected durable reject audit line, got {records}"
    assert "schema:" in matching[-1]["reason"]
    assert "artifact_id" in matching[-1]["reason"]


@pytest.mark.asyncio
async def test_rate_limit_per_plugin(tmp_path, monkeypatch) -> None:
    """Spec §5.3: rate limit is 100 events/minute PER PLUGIN. Two plugins on
    the same engagement must have independent budgets."""
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("FORGE_PLUGIN_EVENT_AUDIT_PATH", str(audit))
    bus = PluginEventBus(max_events_per_minute=3, max_events_per_burst=3)
    await bus.register_publisher(1, "plug-a")
    await bus.register_publisher(1, "plug-b")
    # plug-a exhausts its window on engagement 1.
    for _ in range(3):
        await bus.publish(_mk_event(engagement_id=1, plugin_id="plug-a"))
    with pytest.raises(PluginEventRateLimitError):
        await bus.publish(_mk_event(engagement_id=1, plugin_id="plug-a"))
    # plug-b on the SAME engagement must still have its full budget.
    for _ in range(3):
        await bus.publish(_mk_event(engagement_id=1, plugin_id="plug-b"))
    with pytest.raises(PluginEventRateLimitError):
        await bus.publish(_mk_event(engagement_id=1, plugin_id="plug-b"))
    # Rate-limit rejections are durably audited (spec §5.4).
    records = _read_audit_lines(audit)
    rate_limited = [r for r in records if r["outcome"] == "rate_limited"]
    assert len(rate_limited) >= 2, records
    assert {r["plugin_id"] for r in rate_limited} == {"plug-a", "plug-b"}


@pytest.mark.asyncio
async def test_publisher_engagement_binding_enforced(tmp_path, monkeypatch) -> None:
    """Spec §5.2: `(plugin_id, engagement_id)` binding — a bound plugin cannot
    emit events for engagements outside its binding set."""
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("FORGE_PLUGIN_EVENT_AUDIT_PATH", str(audit))
    bus = PluginEventBus()
    await bus.register_publisher(engagement_id=1, plugin_id="plug-bound")
    # Same engagement → accepted.
    await bus.publish(_mk_event(engagement_id=1, plugin_id="plug-bound"))
    # Different engagement → rejected + audited.
    with pytest.raises(PluginEventBindingError):
        await bus.publish(_mk_event(engagement_id=2, plugin_id="plug-bound"))
    records = _read_audit_lines(audit)
    binding_rejects = [
        r for r in records
        if r["outcome"] == "rejected"
        and r["plugin_id"] == "plug-bound"
        and r["engagement_id"] == 2
        and "bound to engagements" in r["reason"]
    ]
    assert binding_rejects, records


@pytest.mark.asyncio
async def test_publisher_binding_allows_multiple_engagements(tmp_path, monkeypatch) -> None:
    """register_publisher() can bind a plugin to multiple engagements."""
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("FORGE_PLUGIN_EVENT_AUDIT_PATH", str(audit))
    bus = PluginEventBus()
    await bus.register_publisher(engagement_id=1, plugin_id="plug-multi")
    await bus.register_publisher(engagement_id=5, plugin_id="plug-multi")
    await bus.publish(_mk_event(engagement_id=1, plugin_id="plug-multi"))
    await bus.publish(_mk_event(engagement_id=5, plugin_id="plug-multi"))
    with pytest.raises(PluginEventBindingError):
        await bus.publish(_mk_event(engagement_id=9, plugin_id="plug-multi"))


@pytest.mark.asyncio
async def test_unregistered_publish_and_subscribe_fail_closed() -> None:
    bus = PluginEventBus()
    with pytest.raises(PluginEventBindingError, match="not registered"):
        await bus.publish(_mk_event())
    with pytest.raises(PluginEventBindingError, match="not registered"):
        await bus.subscribe(1, "subscriber", lambda _event: None)


@pytest.mark.asyncio
async def test_burst_limit_is_independent_of_minute_limit() -> None:
    bus = PluginEventBus(max_events_per_minute=100, max_events_per_burst=2)
    await bus.register_publisher(1, "plug-a")
    await bus.publish(_mk_event())
    await bus.publish(_mk_event(artifact_id=2))
    with pytest.raises(PluginEventRateLimitError, match="burst"):
        await bus.publish(_mk_event(artifact_id=3))


@pytest.mark.asyncio
async def test_repeated_rate_violations_disable_only_affected_engagement() -> None:
    bus = PluginEventBus(
        max_events_per_minute=100,
        max_events_per_burst=1,
        disable_after_violations=3,
    )
    await bus.register_publisher(1, "plug-a")
    await bus.register_publisher(2, "plug-a")
    await bus.publish(_mk_event(engagement_id=1))
    for artifact_id in (2, 3, 4):
        with pytest.raises(PluginEventRateLimitError):
            await bus.publish(_mk_event(engagement_id=1, artifact_id=artifact_id))
    with pytest.raises(PluginEventDisabledError):
        await bus.publish(_mk_event(engagement_id=1, artifact_id=5))

    # The disable is engagement-local, although the global plugin burst window
    # still applies. Explicit trusted re-registration resets that window.
    await bus.register_publisher(2, "plug-a")
    await bus.publish(_mk_event(engagement_id=2, artifact_id=6))


@pytest.mark.asyncio
async def test_audit_failure_prevents_history_and_delivery(tmp_path, monkeypatch) -> None:
    audit_dir = tmp_path / "audit-is-a-directory"
    audit_dir.mkdir()
    monkeypatch.setenv("FORGE_PLUGIN_EVENT_AUDIT_PATH", str(audit_dir))
    bus = PluginEventBus()
    received: list[PluginEvent] = []
    await bus.register_publisher(1, "plug-a")
    await bus.register_publisher(1, "subscriber")
    await bus.subscribe(1, "subscriber", received.append)

    with pytest.raises(PluginEventAuditError):
        await bus.publish(_mk_event())
    assert received == []
    assert await bus.get_events(1, datetime(2000, 1, 1, tzinfo=UTC)) == []
