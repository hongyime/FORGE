from __future__ import annotations

import sqlite3

from forge.db.control import (
    CONTROL_AUDIT_GENESIS_HASH,
    append_control_audit_event,
    connect_control_db,
    list_control_audit_events,
    verify_control_audit_chain,
)


def test_control_audit_events_are_redacted_and_hash_chained(tmp_path) -> None:
    con = connect_control_db(tmp_path / ".forge_data")
    try:
        first = append_control_audit_event(
            con,
            event_type="workspace_upsert",
            workspace_id="alpha",
            actor_subject="root-admin",
            source="unit",
            payload={
                "metadata": {
                    "tier": "prod",
                    "api_token": "secret-token-never-store",
                }
            },
        )
        second = append_control_audit_event(
            con,
            event_type="membership_upsert",
            workspace_id="alpha",
            actor_subject="root-admin",
            subject="analyst",
            source="unit",
            payload={"role": "viewer", "permissions": ["engagements:read"]},
        )
        con.commit()

        assert first["previous_hash"] == CONTROL_AUDIT_GENESIS_HASH
        assert len(first["event_hash"]) == 64
        assert second["previous_hash"] == first["event_hash"]
        assert verify_control_audit_chain(con) == {
            "valid": True,
            "checked": 2,
            "first_invalid_event_id": None,
            "reason": "",
        }

        raw_payloads = "\n".join(
            row[0] for row in con.execute("SELECT payload_json FROM control_audit_events")
        )
        assert "secret-token-never-store" not in raw_payloads
        assert "[redacted]" in raw_payloads

        events = list_control_audit_events(con, workspace_id="alpha")
        assert [event["event_type"] for event in events] == [
            "membership_upsert",
            "workspace_upsert",
        ]
        assert events[1]["payload"]["metadata"]["api_token"] == "[redacted]"

        try:
            con.execute(
                "UPDATE control_audit_events SET payload_json='{}' WHERE id=?",
                (first["id"],),
            )
        except sqlite3.DatabaseError as exc:
            assert "append-only" in str(exc)
        else:  # pragma: no cover - defensive assertion for SQLite trigger regressions.
            raise AssertionError("control audit UPDATE should be rejected")

        try:
            con.execute("DELETE FROM control_audit_events WHERE id=?", (first["id"],))
        except sqlite3.DatabaseError as exc:
            assert "append-only" in str(exc)
        else:  # pragma: no cover - defensive assertion for SQLite trigger regressions.
            raise AssertionError("control audit DELETE should be rejected")

        assert verify_control_audit_chain(con)["valid"] is True
    finally:
        con.close()
