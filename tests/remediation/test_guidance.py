"""Tests for forge.remediation.guidance (E1.3)."""

from __future__ import annotations

import pytest

from forge.remediation.guidance import (
    SCHEMA_VERSION,
    guidance_for_finding,
    guidance_from_persistence_audit,
    remediate_autorun,
    remediate_event_trigger,
    remediate_hijack_execution,
    remediate_scheduled_task,
)
from forge.hardening.persistence_hardening import (
    detect_persistence_indicators,
    generate_harden_report,
)


REQUIRED_KEYS = {
    "schema_version",
    "threat_type",
    "threat_name",
    "platforms",
    "detection_confirm",
    "remediation_steps",
    "references",
}


@pytest.mark.parametrize(
    ("func", "expected_id", "expected_name_fragment"),
    [
        (remediate_scheduled_task, "T1053", "Scheduled Task"),
        (remediate_autorun, "T1547", "Autostart"),
        (remediate_event_trigger, "T1546", "Event Triggered"),
        (remediate_hijack_execution, "T1574", "Hijack Execution"),
    ],
)
def test_remediation_structure(func, expected_id, expected_name_fragment):
    """Each remediation function returns the schema-conformant dict."""
    g = func()
    assert set(g.keys()) >= REQUIRED_KEYS
    assert g["schema_version"] == SCHEMA_VERSION
    assert g["threat_type"] == expected_id
    assert expected_name_fragment in g["threat_name"]
    assert isinstance(g["remediation_steps"], list) and g["remediation_steps"]
    assert isinstance(g["detection_confirm"], list) and g["detection_confirm"]
    assert isinstance(g["references"], list) and g["references"]
    # Windows and Linux both supported
    assert "windows" in g["platforms"]
    assert "linux" in g["platforms"]


def test_t1053_includes_disable_task_step():
    steps = " ".join(remediate_scheduled_task()["remediation_steps"]).lower()
    assert "disable" in steps and ("schtasks" in steps or "cron" in steps)


def test_t1547_includes_registry_check():
    confirms = " ".join(remediate_autorun()["detection_confirm"]).lower()
    assert "reg query" in confirms or "registry" in confirms
    assert "run" in confirms  # Run/RunOnce keys


def test_t1546_includes_wmi_and_shell_init():
    text = " ".join(
        remediate_event_trigger()["detection_confirm"]
        + remediate_event_trigger()["remediation_steps"]
    ).lower()
    assert "wmi" in text
    assert ".bashrc" in text or "profile" in text


def test_t1574_includes_dll_or_ld_preload():
    text = " ".join(
        remediate_hijack_execution()["detection_confirm"]
        + remediate_hijack_execution()["remediation_steps"]
    ).lower()
    assert "dll" in text or "ld_preload" in text or "ld.so.preload" in text


@pytest.mark.parametrize(
    ("func", "technique_slug"),
    [
        (remediate_scheduled_task, "T1053"),
        (remediate_autorun, "T1547"),
        (remediate_event_trigger, "T1546"),
        (remediate_hijack_execution, "T1574"),
    ],
)
def test_references_link_to_mitre_attack(func, technique_slug):
    refs = func()["references"]
    assert refs, "references must not be empty"
    # Every reference is an HTTPS URL to attack.mitre.org
    for url in refs:
        assert url.startswith("https://attack.mitre.org/"), url
    # At least one reference names the specific parent technique
    assert any(f"/{technique_slug}/" in url for url in refs)


def test_guidance_for_finding_routes_subtechnique():
    """Sub-techniques like T1053.003 route to the parent T1053 function."""
    finding = {"attack_id": "T1053.003", "location": "/etc/crontab"}
    g = guidance_for_finding(finding)
    assert g is not None
    assert g["threat_type"] == "T1053"


def test_guidance_for_finding_unknown_returns_none():
    assert guidance_for_finding({"attack_id": "T9999"}) is None
    assert guidance_for_finding({}) is None


def test_integration_with_persistence_audit():
    """E1.2 -> E1.3 integration: audit report feeds guidance generator."""
    audit = detect_persistence_indicators()
    result = guidance_from_persistence_audit(audit)

    assert result["schema_version"] == "forge.remediation.guidance.audit.v1"
    # T1053 (cron), T1547 (kernel modules / PAM autostart), T1574 not in E1.2
    # baseline but T1053 + T1547 must appear from the built-in checks.
    technique_ids = {t["threat_type"] for t in result["techniques"]}
    assert "T1053" in technique_ids
    assert "T1547" in technique_ids
    # Every finding entry carries a full guidance dict
    assert result["findings"]
    for entry in result["findings"]:
        assert entry["guidance"]["schema_version"] == SCHEMA_VERSION
        assert entry["guidance"]["references"]


def test_integration_with_harden_report():
    """The generate_harden_report shape is also accepted."""
    report = generate_harden_report(engagement_id=42)
    result = guidance_from_persistence_audit(report)
    assert result["engagement_id"] == 42
    assert result["summary"]["technique_count"] >= 1
    assert result["summary"]["finding_count"] >= 1


def test_finding_argument_does_not_break_functions():
    """Each function accepts an optional PersistenceFinding-shaped mapping."""
    finding = {
        "attack_id": "T1053.003",
        "location": "/etc/crontab",
        "severity": "high",
        "platform": "linux",
    }
    for func in (
        remediate_scheduled_task,
        remediate_autorun,
        remediate_event_trigger,
        remediate_hijack_execution,
    ):
        g = func(finding)
        assert set(g.keys()) >= REQUIRED_KEYS


def test_no_offensive_language_in_guidance():
    """Guidance must not reference offensive tradecraft."""
    forbidden = ["install persistence", "reverse shell", "backdoor implant",
                 "evade detection", "bypass av", "anti-forensic"]
    for func in (
        remediate_scheduled_task,
        remediate_autorun,
        remediate_event_trigger,
        remediate_hijack_execution,
    ):
        g = func()
        blob = " ".join(g["remediation_steps"] + g["detection_confirm"]).lower()
        for token in forbidden:
            assert token not in blob, f"{func.__name__} contains forbidden token {token!r}"
