"""
tests/governance/test_policy_engine.py — Unit tests for the policy engine.

Covers rule precedence, default decisions, regex matching, JSON file
loading, GovernanceDeniedError raising via evaluate_or_raise(), and
GOVERNANCE_DECISION audit emission.

Validates Requirements 8.3.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.core.errors import GovernanceDeniedError
from forge.governance import (
    PolicyDecision,
    PolicyEngine,
    PolicyRule,
)


# ── Defaults (no rules) ──────────────────────────────────────────────────────


class TestDefaultDecisions:
    """When no rule matches, decisions follow the risk-level default."""

    def test_no_rules_low_risk_approves(self) -> None:
        engine = PolicyEngine([])
        assert engine.evaluate("tool_x", {}, risk_level="low") is PolicyDecision.APPROVE

    def test_no_rules_medium_requires_review(self) -> None:
        engine = PolicyEngine([])
        assert engine.evaluate("tool_x", {}, risk_level="medium") is PolicyDecision.REQUIRE_REVIEW

    def test_no_rules_high_denies(self) -> None:
        engine = PolicyEngine([])
        assert engine.evaluate("tool_x", {}, risk_level="high") is PolicyDecision.DENY

    def test_no_rules_unknown_risk_approves(self) -> None:
        engine = PolicyEngine([])
        assert engine.evaluate("tool_x", {}, risk_level=None) is PolicyDecision.APPROVE
        assert engine.evaluate("tool_x", {}, risk_level="bogus") is PolicyDecision.APPROVE


# ── Rule matching: regex + first-wins ────────────────────────────────────────


class TestRuleMatching:
    def test_regex_matches_tool_name(self) -> None:
        rule = PolicyRule(
            tool_pattern=r"^nmap_.*",
            risk_level="high",
            action="deny",
        )
        engine = PolicyEngine([rule])
        assert engine.evaluate("nmap_scan", {}, risk_level="high") is PolicyDecision.DENY
        # Pattern does not match: falls back to default for high → DENY.
        # Use medium so we can distinguish "rule didn't match" from "rule matched".
        rule_medium = PolicyRule(
            tool_pattern=r"^nmap_.*",
            risk_level="medium",
            action="approve",
        )
        engine_medium = PolicyEngine([rule_medium])
        # Tool name does not match regex → default for medium = REQUIRE_REVIEW.
        assert (
            engine_medium.evaluate("masscan", {}, risk_level="medium")
            is PolicyDecision.REQUIRE_REVIEW
        )

    def test_first_matching_rule_wins(self) -> None:
        rules = [
            PolicyRule(
                tool_pattern=r"^scan_.*",
                risk_level="medium",
                action="approve",
            ),
            PolicyRule(
                tool_pattern=r"^scan_aggressive$",
                risk_level="medium",
                action="deny",
            ),
        ]
        engine = PolicyEngine(rules)
        # Although the second rule would deny, the first one matches first.
        assert engine.evaluate("scan_aggressive", {}, risk_level="medium") is PolicyDecision.APPROVE

    def test_risk_level_must_match_when_supplied(self) -> None:
        rule = PolicyRule(
            tool_pattern=r"^exploit$",
            risk_level="high",
            action="deny",
        )
        engine = PolicyEngine([rule])
        # Caller asserts low risk → rule does not match → default for low = APPROVE.
        assert engine.evaluate("exploit", {}, risk_level="low") is PolicyDecision.APPROVE
        # Caller asserts high risk → rule matches → DENY.
        assert engine.evaluate("exploit", {}, risk_level="high") is PolicyDecision.DENY

    def test_risk_level_ignored_when_not_supplied(self) -> None:
        rule = PolicyRule(
            tool_pattern=r"^exploit$",
            risk_level="high",
            action="deny",
        )
        engine = PolicyEngine([rule])
        assert engine.evaluate("exploit", {}, risk_level=None) is PolicyDecision.DENY

    def test_conditions_must_match(self) -> None:
        rule = PolicyRule(
            tool_pattern=r"^delete_resource$",
            risk_level="high",
            action="deny",
            conditions={"environment": "production"},
        )
        engine = PolicyEngine([rule])
        # Production matches the condition → DENY.
        assert (
            engine.evaluate(
                "delete_resource",
                {"environment": "production"},
                risk_level="high",
            )
            is PolicyDecision.DENY
        )
        # Staging fails the condition → default for high = DENY anyway.
        # Use medium-risk caller and approve action to distinguish.
        rule_medium = PolicyRule(
            tool_pattern=r"^delete_resource$",
            risk_level="medium",
            action="approve",
            conditions={"environment": "staging"},
        )
        engine_medium = PolicyEngine([rule_medium])
        # Mismatched condition → no rule matches → default for medium = REQUIRE_REVIEW.
        assert (
            engine_medium.evaluate(
                "delete_resource",
                {"environment": "production"},
                risk_level="medium",
            )
            is PolicyDecision.REQUIRE_REVIEW
        )

    def test_invalid_regex_is_skipped(self) -> None:
        bad_rule = PolicyRule(
            tool_pattern=r"[unclosed",
            risk_level="high",
            action="deny",
        )
        good_rule = PolicyRule(
            tool_pattern=r"^safe_tool$",
            risk_level="low",
            action="approve",
        )
        engine = PolicyEngine([bad_rule, good_rule])
        # Bad rule is skipped silently; good rule still matches.
        assert engine.evaluate("safe_tool", {}, risk_level="low") is PolicyDecision.APPROVE

    def test_require_review_action(self) -> None:
        rule = PolicyRule(
            tool_pattern=r"^audit$",
            risk_level="medium",
            action="require_review",
        )
        engine = PolicyEngine([rule])
        assert engine.evaluate("audit", {}, risk_level="medium") is PolicyDecision.REQUIRE_REVIEW


# ── from_file / from_env ─────────────────────────────────────────────────────


class TestLoading:
    def test_from_file_loads_rules(self, tmp_path: Path) -> None:
        rules_path = tmp_path / "rules.json"
        rules_path.write_text(
            json.dumps(
                [
                    {
                        "tool_pattern": r"^danger_.*",
                        "risk_level": "high",
                        "action": "deny",
                    },
                    {
                        "tool_pattern": r"^safe_.*",
                        "risk_level": "low",
                        "action": "approve",
                    },
                ]
            ),
            encoding="utf-8",
        )
        engine = PolicyEngine.from_file(rules_path)
        assert len(engine.rules) == 2
        assert engine.evaluate("danger_run", {}, risk_level="high") is PolicyDecision.DENY
        assert engine.evaluate("safe_check", {}, risk_level="low") is PolicyDecision.APPROVE

    def test_from_file_rejects_non_array(self, tmp_path: Path) -> None:
        rules_path = tmp_path / "bad.json"
        rules_path.write_text(json.dumps({"not": "array"}), encoding="utf-8")
        with pytest.raises(ValueError):
            PolicyEngine.from_file(rules_path)

    def test_from_file_rejects_invalid_rule(self, tmp_path: Path) -> None:
        rules_path = tmp_path / "bad.json"
        # action="invalid" is not in the Literal set.
        rules_path.write_text(
            json.dumps(
                [
                    {
                        "tool_pattern": r"^x$",
                        "risk_level": "low",
                        "action": "invalid",
                    }
                ]
            ),
            encoding="utf-8",
        )
        with pytest.raises(Exception):  # Pydantic ValidationError
            PolicyEngine.from_file(rules_path)

    def test_from_env_unset_returns_empty_engine(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FORGE_GOVERNANCE_RULES", raising=False)
        engine = PolicyEngine.from_env()
        assert engine.rules == []

    def test_from_env_loads_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        rules_path = tmp_path / "rules.json"
        rules_path.write_text(
            json.dumps(
                [
                    {
                        "tool_pattern": r"^x$",
                        "risk_level": "high",
                        "action": "deny",
                    }
                ]
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("FORGE_GOVERNANCE_RULES", str(rules_path))
        engine = PolicyEngine.from_env()
        assert len(engine.rules) == 1


# ── evaluate_or_raise ────────────────────────────────────────────────────────


class TestEvaluateOrRaise:
    def test_raises_on_deny(self) -> None:
        rule = PolicyRule(
            tool_pattern=r"^bad$",
            risk_level="high",
            action="deny",
        )
        engine = PolicyEngine([rule])
        with pytest.raises(GovernanceDeniedError):
            asyncio.run(engine.evaluate_or_raise("bad", {}, risk_level="high"))

    def test_returns_decision_on_approve(self) -> None:
        rule = PolicyRule(
            tool_pattern=r"^ok$",
            risk_level="low",
            action="approve",
        )
        engine = PolicyEngine([rule])
        decision = asyncio.run(engine.evaluate_or_raise("ok", {}, risk_level="low"))
        assert decision is PolicyDecision.APPROVE

    def test_returns_decision_on_require_review(self) -> None:
        rule = PolicyRule(
            tool_pattern=r"^review$",
            risk_level="medium",
            action="require_review",
        )
        engine = PolicyEngine([rule])
        decision = asyncio.run(engine.evaluate_or_raise("review", {}, risk_level="medium"))
        assert decision is PolicyDecision.REQUIRE_REVIEW


# ── Audit emission ───────────────────────────────────────────────────────────


class TestAuditEmission:
    def test_audit_entry_emitted_on_approve(self) -> None:
        logger = AuditLogger()
        rule = PolicyRule(
            tool_pattern=r"^safe$",
            risk_level="low",
            action="approve",
        )
        engine = PolicyEngine([rule], audit_logger=logger)
        decision = engine.evaluate("safe", {"x": 1}, risk_level="low", correlation_id="corr-ok")
        assert decision is PolicyDecision.APPROVE

        gov_entries = [
            e for e in logger.entries if e.event_type == AuditEventType.GOVERNANCE_DECISION
        ]
        assert len(gov_entries) == 1
        entry = gov_entries[0]
        assert entry.correlation_id == "corr-ok"
        assert entry.tool_name == "safe"
        assert entry.success is True
        assert entry.input_params == {"x": 1}
        assert "approve" in (entry.output_summary or "")

    def test_audit_entry_emitted_on_deny(self) -> None:
        logger = AuditLogger()
        rule = PolicyRule(
            tool_pattern=r"^bad$",
            risk_level="high",
            action="deny",
        )
        engine = PolicyEngine([rule], audit_logger=logger)
        decision = engine.evaluate("bad", {}, risk_level="high", correlation_id="corr-deny")
        assert decision is PolicyDecision.DENY

        gov_entries = [
            e for e in logger.entries if e.event_type == AuditEventType.GOVERNANCE_DECISION
        ]
        assert len(gov_entries) == 1
        entry = gov_entries[0]
        assert entry.correlation_id == "corr-deny"
        assert entry.success is False
        assert entry.error_detail == "policy_denied"
        assert "deny" in (entry.output_summary or "")

    def test_audit_emission_inside_event_loop(self) -> None:
        """evaluate() called inside a running loop schedules the audit log."""
        logger = AuditLogger()
        engine = PolicyEngine([], audit_logger=logger)

        async def _drive() -> None:
            engine.evaluate("any_tool", {}, risk_level="low", correlation_id="corr-loop")
            # Yield so the scheduled task can execute.
            await asyncio.sleep(0)

        asyncio.run(_drive())
        gov_entries = [
            e for e in logger.entries if e.event_type == AuditEventType.GOVERNANCE_DECISION
        ]
        assert any(e.correlation_id == "corr-loop" for e in gov_entries)

    def test_audit_secrets_redacted_in_params(self) -> None:
        """Audit logger redacts secrets in input_params."""
        logger = AuditLogger()
        engine = PolicyEngine([], audit_logger=logger)
        engine.evaluate(
            "x",
            {"password": "hunter2", "user": "alice"},
            risk_level="low",
            correlation_id="corr-redact",
        )
        entries = [e for e in logger.entries if e.correlation_id == "corr-redact"]
        assert len(entries) == 1
        params = entries[0].input_params or {}
        assert params.get("password") == "[REDACTED]"
        assert params.get("user") == "alice"

    def test_no_logger_no_emission(self) -> None:
        """Engine works fine without an audit logger."""
        engine = PolicyEngine([])
        # Must not raise.
        assert engine.evaluate("x", {}, risk_level="low") is PolicyDecision.APPROVE
