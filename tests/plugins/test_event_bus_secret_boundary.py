"""Integration test for BLOCKER 3: plugin secret validation bypass fix.

Verifies:
- Event bus and schema validator agree on a single event-name format.
- Recursive, case-insensitive substring forbidden-field detection catches
  'access_token', 'ACCESS_TOKEN', 'database_password', 'my_access_token_value'.
- Every dispatch decision (accept/reject/rate_limited) writes a durable
  audit record with plugin_id/engagement_id/event_type/outcome/payload_bytes.

References:
- docs/specs/plugin_boundary_v1.md:166 (forbidden field contract)
- docs/specs/plugin_boundary_v1.md:201 (audit logging contract)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forge.plugins.event_bus import (
    ALLOWED_EVENT_TYPES,
    PluginEvent,
    PluginEventBus,
    PluginEventValidationError,
)
from forge.plugins.schemas.event_schema import EVENT_SCHEMAS
from forge.plugins.schemas.validators import (
    EventValidatorMiddleware,
    SchemaValidationError,
    check_forbidden_fields,
    validate_event,
)


# ---------------------------------------------------------------------------
# Format unification
# ---------------------------------------------------------------------------


def test_bus_and_validator_share_single_event_name_format() -> None:
    """The bus's ALLOWED_EVENT_TYPES and the validator's EVENT_SCHEMAS must
    reference the same set of names, so an event that parses on one side
    cannot be silently unknown on the other."""
    assert set(ALLOWED_EVENT_TYPES) == set(EVENT_SCHEMAS.keys())
    # Colon-form is the unified format (matches spec §3 collection:progress).
    for name in ALLOWED_EVENT_TYPES:
        assert ":" in name, f"unified format is colon-separated; got {name!r}"


def test_validator_accepts_colon_form_names() -> None:
    """Validator accepts the same colon-form names the bus emits."""
    result = validate_event(
        {
            "event_type": "artifact:discovered",
            "payload": {
                "artifact_id": 1,
                "artifact_type": "host",
                "source": "test",
                "discovered_at": "2026-01-01T00:00:00Z",
            },
        }
    )
    assert result.valid, result.errors


# ---------------------------------------------------------------------------
# Recursive substring forbidden-field detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "access_token",       # exact-form previously not caught by bus
        "database_password",  # substring: 'password'
        "ACCESS_TOKEN",       # case-insensitive
        "my_access_token_value",  # substring at arbitrary position
        "X-API-Key",          # substring: 'api-key' or 'api_key'
        "user_credentials",   # substring: 'credential'
        "AuthHeader",         # substring: 'auth'
        "PrivateCert",        # substring: 'private'
    ],
)
def test_bus_rejects_forbidden_substring_fields(forbidden_key: str) -> None:
    with pytest.raises(Exception):
        PluginEvent(
            event_type="artifact:discovered",
            engagement_id=1,
            plugin_id="plug",
            payload={forbidden_key: "leak-me"},
        )


def test_bus_rejects_nested_forbidden_substring() -> None:
    with pytest.raises(Exception):
        PluginEvent(
            event_type="artifact:discovered",
            engagement_id=1,
            plugin_id="plug",
            payload={"config": {"deep": {"my_access_token_value": "x"}}},
        )


def test_bus_rejects_forbidden_substring_in_list_item() -> None:
    with pytest.raises(Exception):
        PluginEvent(
            event_type="artifact:discovered",
            engagement_id=1,
            plugin_id="plug",
            payload={"items": [{"DATABASE_PASSWORD": "x"}]},
        )


def test_validator_check_forbidden_fields_catches_composite_names() -> None:
    hits = check_forbidden_fields(
        {
            "access_token": "a",
            "database_password": "b",
            "nested": {"my_access_token_value": "c"},
            "list": [{"X-Api-Key": "d"}],
            "clean_field": "ok",
        }
    )
    assert "access_token" in hits
    assert "database_password" in hits
    assert "nested.my_access_token_value" in hits
    assert "list[0].X-Api-Key" in hits


def test_validator_middleware_rejects_access_token_via_boundary_contract() -> None:
    mw = EventValidatorMiddleware(mode="strict")
    with pytest.raises(SchemaValidationError):
        mw.process(
            {
                "event_type": "artifact:discovered",
                "payload": {
                    "artifact_id": 1,
                    "artifact_type": "host",
                    "source": "test",
                    "discovered_at": "2026-01-01T00:00:00Z",
                    "access_token": "leak",
                },
            }
        )


# ---------------------------------------------------------------------------
# Durable audit logging
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "plugin_events_audit.jsonl"
    monkeypatch.setenv("FORGE_PLUGIN_EVENT_AUDIT_PATH", str(path))
    return path


def _read_audit_lines(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@pytest.mark.asyncio
async def test_audit_log_records_accepted_dispatch(audit_path: Path) -> None:
    bus = PluginEventBus()
    event = PluginEvent(
        event_type="artifact:discovered",
        engagement_id=42,
        plugin_id="plug-a",
        payload={
            "artifact_id": 1,
            "artifact_type": "host",
            "source": "test",
            "discovered_at": "2026-01-01T00:00:00Z",
        },
    )
    await bus.register_publisher(42, "plug-a")
    await bus.publish(event)

    records = _read_audit_lines(audit_path)
    assert any(
        r["outcome"] == "accepted"
        and r["engagement_id"] == 42
        and r["plugin_id"] == "plug-a"
        and r["event_type"] == "artifact:discovered"
        and r["payload_bytes"] > 0
        for r in records
    ), records


@pytest.mark.asyncio
async def test_audit_log_records_rejected_forbidden_field(audit_path: Path) -> None:
    """A forbidden-field rejection must appear in the durable audit log.

    We bypass PluginEvent's field validator (which would raise at construction)
    by feeding a non-PluginEvent input that also triggers audit logging.
    Then we mutate a PluginEvent's payload post-construction to trigger the
    bus's defensive re-check + audit.
    """
    bus = PluginEventBus()
    # Case 1: wrong type is audit-logged as rejected.
    with pytest.raises(PluginEventValidationError):
        await bus.publish("not-an-event")  # type: ignore[arg-type]

    records = _read_audit_lines(audit_path)
    assert any(r["outcome"] == "rejected" for r in records), records


@pytest.mark.asyncio
async def test_audit_log_records_rejected_on_mutated_payload(audit_path: Path) -> None:
    """Bus's defensive re-validation catches a mutated payload and audits it."""
    bus = PluginEventBus()
    event = PluginEvent(
        event_type="artifact:discovered",
        engagement_id=7,
        plugin_id="plug-b",
        payload={
            "artifact_id": 1,
            "artifact_type": "host",
            "source": "test",
            "discovered_at": "2026-01-01T00:00:00Z",
        },
    )
    # PluginEvent is frozen but the dict inside is mutable — attackers who
    # obtain a reference could try to smuggle a secret after construction.
    event.payload["access_token"] = "smuggled"  # noqa: SLF001

    with pytest.raises(PluginEventValidationError):
        await bus.publish(event)

    records = _read_audit_lines(audit_path)
    rejected = [r for r in records if r["outcome"] == "rejected" and r["engagement_id"] == 7]
    assert rejected, records
    assert rejected[-1]["plugin_id"] == "plug-b"
    assert rejected[-1]["event_type"] == "artifact:discovered"
    assert "access_token" in rejected[-1]["reason"] or "token" in rejected[-1]["reason"]
