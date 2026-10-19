from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.governance.rules import (
    ALLOWED_TARGET_TYPES,
    PolicyViolation,
    attack_mapping_for,
    deny_prohibited_activity,
    routine_finding_automation,
)
from forge.governance.scope_gate import EngagementScope, ScopeGate
from forge.governance.review import confirm_high_severity_finding
from forge.phase5.approval_gate import ActionClassification, request_approval
from forge.targets_import import (
    _coerce_feed_item,
    _item_is_human_authorized,
    _load_human_authorized_scope,
)


def test_prohibited_activity_is_blocked() -> None:
    for activity in ("exploitation", "defense evasion", "persistence", "lateral movement"):
        with pytest.raises(PolicyViolation, match="prohibits"):
            deny_prohibited_activity(activity)


def test_payload_generation_and_waf_evasion_entrypoints_are_blocked() -> None:
    from forge.hardening.linper_offensive import (
        PersistenceMethod,
        generate_reverse_shell_command,
    )
    from forge.phase3.obfuscator import ObfuscationEngine
    from forge.phase3.payload_builder import HTMLSmuggler, PayloadBuilder
    from forge.utils.playbooks.waf_evasion import run_waf_evasion_playbook
    from forge.utils.post.template_engine import ReverseShellGenerator

    with pytest.raises(PolicyViolation, match="prohibits"):
        PayloadBuilder().build("powershell_reverse.j2", {})
    with pytest.raises(PolicyViolation, match="prohibits"):
        ObfuscationEngine().obfuscate("Write-Output safe", target="powershell")
    with pytest.raises(PolicyViolation, match="prohibits"):
        HTMLSmuggler().build(b"payload", "document.bin")
    with pytest.raises(PolicyViolation, match="prohibits"):
        ReverseShellGenerator(Path("unused.db")).generate("bash", "127.0.0.1", 443)
    with pytest.raises(PolicyViolation, match="prohibits"):
        generate_reverse_shell_command(PersistenceMethod.BASH, "127.0.0.1", 443)
    with pytest.raises(PolicyViolation, match="prohibits"):
        run_waf_evasion_playbook(1, "example.com", [], sqlite3.connect(":memory:"))


def test_supported_target_types_are_closed_set() -> None:
    assert ALLOWED_TARGET_TYPES == {"url", "domain", "ipv4", "cloud_ref"}


@pytest.mark.parametrize(
    ("label", "tactic", "technique"),
    [
        ("routine scan", "TA0043", "T1595"),
        ("AWS_MISCONFIG", "TA0007", "T1580"),
        ("EXPOSED_CREDENTIAL", "TA0006", "T1552.001"),
        ("unclassified finding", "TA0001", "T1190"),
    ],
)
def test_every_check_or_finding_has_a_complete_attack_mapping(
    label: str, tactic: str, technique: str
) -> None:
    mapping = attack_mapping_for(label)
    assert mapping.tactics == (tactic,)
    assert mapping.techniques == (technique,)


def test_routine_findings_are_auto_triaged_prioritized_and_queued_for_reporting() -> None:
    assert routine_finding_automation("medium") == ("triaged", 60, "queued")


def test_persistent_import_requires_specific_human_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FORGE_SCOPE_JSON", raising=False)
    with pytest.raises(ValueError, match="human-set specific"):
        _load_human_authorized_scope()

    monkeypatch.setenv("FORGE_SCOPE_JSON", json.dumps({"domains": ["*"]}))
    with pytest.raises(ValueError, match="wildcards do not authorize"):
        _load_human_authorized_scope()

    monkeypatch.setenv("FORGE_SCOPE_JSON", json.dumps({"domains": ["corp-target.io"]}))
    scope = _load_human_authorized_scope()
    allowed = _coerce_feed_item({"target_type": "domain", "target_value": "corp-target.io"})
    outside = _coerce_feed_item({"target_type": "domain", "target_value": "outside.org"})
    assert allowed is not None and _item_is_human_authorized(allowed, scope)
    assert outside is not None and not _item_is_human_authorized(outside, scope)


def test_wildcard_scope_values_do_not_authorize_targets() -> None:
    cases = (
        EngagementScope(roe_scope="*"),
        EngagementScope(domains=["*.example.test"]),
        EngagementScope(ip_ranges=["0.0.0.0/0"]),
        EngagementScope(urls=["*"]),
    )
    for scope in cases:
        assert not ScopeGate(scope).is_in_scope("www.example.test")
        assert not ScopeGate(scope).is_in_scope("192.0.2.3")


def test_destructive_action_cannot_be_enabled_by_attack_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORGE_SAFE_MODE", "0")
    monkeypatch.setenv("FORGE_ATTACK_MODE_AUTO", "1")
    db = sqlite3.connect(":memory:")
    db.execute(
        "CREATE TABLE audit_log (engagement_id, phase, module, action, target, result, operator, logged_at)"
    )

    assert not request_approval(
        "persistence_deploy",
        "deploy persistence",
        1,
        db,
        ActionClassification.DESTRUCTIVE,
    )
    assert db.execute("SELECT result FROM audit_log").fetchone()[0] == (
        "blocked_by_canonical_policy"
    )


@pytest.mark.parametrize(
    "classification", [ActionClassification.PASSIVE, ActionClassification.ACTIVE]
)
def test_routine_actions_remain_automated_and_audited(
    classification: ActionClassification,
) -> None:
    db = sqlite3.connect(":memory:")
    db.execute(
        "CREATE TABLE audit_log (engagement_id, phase, module, action, target, result, operator, logged_at)"
    )

    assert request_approval("routine_scan", "routine assessment", 1, db, classification)
    assert db.execute("SELECT result FROM audit_log").fetchone()[0] == "auto_approved"


@pytest.mark.parametrize(
    ("vuln_type", "expected_tactic", "expected_technique"),
    [
        ("IDOR", ["TA0001"], ["T1190"]),
        ("AWS_MISCONFIG", ["TA0007"], ["T1580"]),
        ("EXPOSED_CREDENTIAL", ["TA0006"], ["T1552.001"]),
    ],
)
def test_vulnerability_findings_receive_attack_mapping(
    vuln_type: str,
    expected_tactic: list[str],
    expected_technique: list[str],
) -> None:
    conn = sqlite3.connect(":memory:")
    apply_schema(conn)
    run_migrations(conn)
    conn.execute("INSERT INTO engagements (name, operator) VALUES ('test', 'test')")
    engagement_id = int(conn.execute("SELECT id FROM engagements").fetchone()[0])
    conn.execute(
        """INSERT INTO vulnerability_findings
           (engagement_id, vuln_type, target_url, severity, title)
           VALUES (?, ?, 'https://example.test/', 'MEDIUM', 'finding')""",
        (engagement_id, vuln_type),
    )
    tactics, techniques = conn.execute(
        "SELECT attack_tactics, attack_techniques FROM vulnerability_findings"
    ).fetchone()
    assert json.loads(tactics) == expected_tactic
    assert json.loads(techniques) == expected_technique


def test_finding_insert_is_auto_triaged_prioritized_and_queued_for_reporting() -> None:
    conn = sqlite3.connect(":memory:")
    apply_schema(conn)
    run_migrations(conn)
    conn.execute("INSERT INTO engagements (name, operator) VALUES ('test', 'test')")
    engagement_id = int(conn.execute("SELECT id FROM engagements").fetchone()[0])
    conn.execute(
        """INSERT INTO vulnerability_findings
           (engagement_id, vuln_type, target_url, severity, title)
           VALUES (?, 'INFO', 'https://example.test/', 'MEDIUM', 'finding')""",
        (engagement_id,),
    )
    assert conn.execute(
        """SELECT triage_status, priority_score, reporting_status,
                  attack_tactics, attack_techniques
           FROM vulnerability_findings"""
    ).fetchone() == ("triaged", 60, "queued", '["TA0043"]', '["T1595"]')


def test_high_severity_confirmation_requires_named_human_and_is_audited() -> None:
    conn = sqlite3.connect(":memory:")
    apply_schema(conn)
    run_migrations(conn)
    conn.execute("INSERT INTO engagements (name, operator) VALUES ('test', 'test')")
    engagement_id = int(conn.execute("SELECT id FROM engagements").fetchone()[0])
    conn.execute(
        """INSERT INTO vulnerability_findings
           (engagement_id, vuln_type, target_url, severity, title)
           VALUES (?, 'IDOR', 'https://example.test/', 'HIGH', 'finding')""",
        (engagement_id,),
    )
    finding_id = int(conn.execute("SELECT id FROM vulnerability_findings").fetchone()[0])
    assert (
        conn.execute(
            "SELECT severity_confirmation_status FROM vulnerability_findings WHERE id=?",
            (finding_id,),
        ).fetchone()[0]
        == "pending"
    )
    with pytest.raises(ValueError, match="named human reviewer"):
        confirm_high_severity_finding(conn, finding_id, reviewer=" ")

    confirm_high_severity_finding(conn, finding_id, reviewer="Bryan")

    status, reviewer = conn.execute(
        "SELECT severity_confirmation_status, severity_reviewed_by "
        "FROM vulnerability_findings WHERE id=?",
        (finding_id,),
    ).fetchone()
    assert (status, reviewer) == ("confirmed", "Bryan")
    audit = conn.execute(
        "SELECT action, operator FROM audit_log WHERE engagement_id=?",
        (engagement_id,),
    ).fetchone()
    assert audit == ("high_severity_confirmed", "Bryan")
