"""
tests/properties/test_property_26_governance_policy.py
Property 26: Governance policy enforcement
Validates Requirements 8.3.

The Governance Agent reviews tool invocations and approves or denies
execution based on configured policy rules. The PolicyEngine evaluates
rules in declaration order (first-match-wins) and falls back to a
risk-level-driven default when no rule matches.

The test asserts these invariants:

  1. Static invariant - PolicyDecision has exactly three values:
     APPROVE, DENY, REQUIRE_REVIEW.

  2. Dynamic invariant (default decisions) - with NO rules configured:
       a. risk_level="high"   -> DENY
       b. risk_level="medium" -> REQUIRE_REVIEW
       c. risk_level="low" or None -> APPROVE

  3. Dynamic invariant (rule precedence) - rules are evaluated in
     declaration order; the first matching rule wins regardless of any
     later conflicting rule.

  4. Dynamic invariant (audit completeness) - every evaluate() call emits
     EXACTLY ONE GOVERNANCE_DECISION audit entry whose success flag
     matches the decision (success=False iff decision == DENY).

  5. Dynamic invariant (evaluate_or_raise) - DENY decisions raise
     :class:`GovernanceDeniedError`; APPROVE and REQUIRE_REVIEW return
     the decision unchanged.

  6. Dynamic invariant (regex matching) - tool_pattern is a regex; only
     tool names matching the pattern can trigger the rule.
"""

from __future__ import annotations

import string
from typing import Literal

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.core.errors import GovernanceDeniedError
from forge.governance import PolicyDecision, PolicyEngine, PolicyRule


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


_TOOL_NAME_CHAR = string.ascii_lowercase + string.digits + "_"
_tool_name = st.text(alphabet=st.sampled_from(_TOOL_NAME_CHAR), min_size=3, max_size=16)
_risk_levels: tuple[Literal["high"], Literal["medium"], Literal["low"]] = ("high", "medium", "low")
_risk = st.sampled_from(_risk_levels)
_action = st.sampled_from(("approve", "deny", "require_review"))


# ---------------------------------------------------------------------------
# Static invariants
# ---------------------------------------------------------------------------


class TestEnumShape:
    """PolicyDecision exposes exactly three values."""

    def test_decision_values(self) -> None:
        assert {d.value for d in PolicyDecision} == {
            "approve",
            "deny",
            "require_review",
        }


# ---------------------------------------------------------------------------
# Default decisions (no rules configured)
# ---------------------------------------------------------------------------


class TestDefaultDecisions:
    """With no rules: high->DENY, medium->REQUIRE_REVIEW, low/None->APPROVE."""

    @given(tool=_tool_name)
    @settings(max_examples=20, deadline=None)
    def test_high_risk_default_denies(self, tool: str) -> None:
        engine = PolicyEngine(rules=[])
        decision = engine.evaluate(tool, params={}, risk_level="high")
        assert decision is PolicyDecision.DENY

    @given(tool=_tool_name)
    @settings(max_examples=20, deadline=None)
    def test_medium_risk_default_requires_review(self, tool: str) -> None:
        engine = PolicyEngine(rules=[])
        decision = engine.evaluate(tool, params={}, risk_level="medium")
        assert decision is PolicyDecision.REQUIRE_REVIEW

    @given(tool=_tool_name)
    @settings(max_examples=20, deadline=None)
    def test_low_risk_default_approves(self, tool: str) -> None:
        engine = PolicyEngine(rules=[])
        decision = engine.evaluate(tool, params={}, risk_level="low")
        assert decision is PolicyDecision.APPROVE

    @given(tool=_tool_name)
    @settings(max_examples=20, deadline=None)
    def test_unknown_risk_default_approves(self, tool: str) -> None:
        engine = PolicyEngine(rules=[])
        decision = engine.evaluate(tool, params={}, risk_level=None)
        assert decision is PolicyDecision.APPROVE


# ---------------------------------------------------------------------------
# Rule precedence - first match wins
# ---------------------------------------------------------------------------


class TestRulePrecedence:
    """Rules are evaluated in declaration order; first match wins."""

    def test_first_rule_wins_even_when_later_rules_disagree(self) -> None:
        # Two rules both match "exfil_data" but the first denies and the
        # second approves; first must win.
        engine = PolicyEngine(
            rules=[
                PolicyRule(
                    tool_pattern=r"^exfil",
                    risk_level="high",
                    action="deny",
                ),
                PolicyRule(
                    tool_pattern=r"^exfil",
                    risk_level="high",
                    action="approve",
                ),
            ]
        )
        decision = engine.evaluate(
            "exfil_data", params={}, risk_level="high"
        )
        assert decision is PolicyDecision.DENY

    def test_non_matching_rule_skipped(self) -> None:
        engine = PolicyEngine(
            rules=[
                PolicyRule(
                    tool_pattern=r"^never_match$",
                    risk_level="high",
                    action="deny",
                ),
                PolicyRule(
                    tool_pattern=r"^.+$",
                    risk_level="low",
                    action="approve",
                ),
            ]
        )
        decision = engine.evaluate(
            "anything_at_all", params={}, risk_level="low"
        )
        assert decision is PolicyDecision.APPROVE

    @given(
        action=_action,
        tool=_tool_name,
        risk=_risk,
    )
    @settings(max_examples=30, deadline=None)
    def test_action_field_drives_outcome(
        self,
        action: Literal["approve", "deny", "require_review"],
        tool: str,
        risk: Literal["high", "medium", "low"],
    ) -> None:
        engine = PolicyEngine(
            rules=[
                PolicyRule(
                    tool_pattern=r"^.+$",  # match anything
                    risk_level=risk,
                    action=action,
                )
            ]
        )
        decision = engine.evaluate(tool, params={}, risk_level=risk)
        expected = {
            "approve": PolicyDecision.APPROVE,
            "deny": PolicyDecision.DENY,
            "require_review": PolicyDecision.REQUIRE_REVIEW,
        }[action]
        assert decision is expected


# ---------------------------------------------------------------------------
# Regex matching
# ---------------------------------------------------------------------------


class TestRegexMatching:
    """tool_pattern is a regex; non-matching names skip the rule."""

    def test_only_matching_tool_names_trigger_rule(self) -> None:
        engine = PolicyEngine(
            rules=[
                PolicyRule(
                    tool_pattern=r"^danger_",
                    risk_level="high",
                    action="deny",
                )
            ]
        )
        # Matches the pattern -> denied (also default for high)
        d1 = engine.evaluate(
            "danger_payload", params={}, risk_level="high"
        )
        assert d1 is PolicyDecision.DENY

        # Does not match the pattern -> default for low risk
        d2 = engine.evaluate("safe_query", params={}, risk_level="low")
        assert d2 is PolicyDecision.APPROVE

    def test_invalid_regex_is_skipped_not_fatal(self) -> None:
        # Invalid regex should be skipped with a warning, not crash the engine.
        engine = PolicyEngine(
            rules=[
                PolicyRule(
                    tool_pattern=r"[unclosed",
                    risk_level="high",
                    action="deny",
                )
            ]
        )
        # Engine still functional - falls through to default
        decision = engine.evaluate("anything", params={}, risk_level="low")
        assert decision is PolicyDecision.APPROVE


# ---------------------------------------------------------------------------
# Conditions matching
# ---------------------------------------------------------------------------


class TestConditionsMatching:
    """conditions dict requires every key/value to be present in params."""

    def test_conditions_must_match_params(self) -> None:
        engine = PolicyEngine(
            rules=[
                PolicyRule(
                    tool_pattern=r"^.+$",
                    risk_level="medium",
                    action="deny",
                    conditions={"env": "prod"},
                )
            ]
        )
        # Conditions match -> rule fires
        assert (
            engine.evaluate("any", params={"env": "prod"}, risk_level="medium")
            is PolicyDecision.DENY
        )
        # Conditions miss -> rule skipped, falls through to default
        assert (
            engine.evaluate("any", params={"env": "dev"}, risk_level="medium")
            is PolicyDecision.REQUIRE_REVIEW
        )
        # Param missing -> rule skipped
        assert (
            engine.evaluate("any", params={}, risk_level="medium")
            is PolicyDecision.REQUIRE_REVIEW
        )


# ---------------------------------------------------------------------------
# evaluate_or_raise contract
# ---------------------------------------------------------------------------


class TestEvaluateOrRaise:
    """DENY raises; APPROVE/REQUIRE_REVIEW return the decision."""

    @pytest.mark.asyncio
    async def test_deny_raises_governance_denied(self) -> None:
        engine = PolicyEngine(rules=[])
        with pytest.raises(GovernanceDeniedError):
            await engine.evaluate_or_raise(
                "any", params={}, risk_level="high"
            )

    @pytest.mark.asyncio
    async def test_approve_returns_decision(self) -> None:
        engine = PolicyEngine(rules=[])
        decision = await engine.evaluate_or_raise(
            "any", params={}, risk_level="low"
        )
        assert decision is PolicyDecision.APPROVE

    @pytest.mark.asyncio
    async def test_require_review_returns_decision(self) -> None:
        engine = PolicyEngine(rules=[])
        decision = await engine.evaluate_or_raise(
            "any", params={}, risk_level="medium"
        )
        assert decision is PolicyDecision.REQUIRE_REVIEW


# ---------------------------------------------------------------------------
# Audit emission contract
# ---------------------------------------------------------------------------


class TestAuditContract:
    """evaluate() emits exactly one GOVERNANCE_DECISION entry per call."""

    @given(
        tool=_tool_name,
        risk=_risk,
        correlation=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=12),
    )
    @settings(max_examples=20, deadline=None)
    def test_one_audit_entry_per_evaluate_call(
        self,
        tool: str,
        risk: Literal["high", "medium", "low"],
        correlation: str,
    ) -> None:
        audit = AuditLogger()
        engine = PolicyEngine(rules=[], audit_logger=audit)

        decision = engine.evaluate(
            tool,
            params={"key": "value"},
            risk_level=risk,
            correlation_id=correlation,
        )

        gov_entries = [
            e
            for e in audit.entries
            if e.event_type == AuditEventType.GOVERNANCE_DECISION
        ]
        assert len(gov_entries) == 1
        entry = gov_entries[0]
        assert entry.correlation_id == correlation
        assert entry.tool_name == tool
        # success flag mirrors the decision
        if decision is PolicyDecision.DENY:
            assert entry.success is False
            assert entry.error_detail == "policy_denied"
        else:
            assert entry.success is True
            assert entry.error_detail is None
