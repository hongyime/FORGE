"""
forge/governance/policy_engine.py — Rule-based governance policy engine.

Evaluates tool invocations against an ordered list of :class:`PolicyRule`
definitions and returns an :class:`PolicyDecision` (``APPROVE``, ``DENY``,
or ``REQUIRE_REVIEW``). Every evaluation, regardless of outcome, is emitted
as a ``GOVERNANCE_DECISION`` audit entry so the engagement record contains
a complete trace of every policy decision made by the platform.

Rule semantics:

* Rules are evaluated in declaration order — **first matching rule wins**.
* A rule matches when the ``tool_pattern`` regex matches ``tool_name`` and,
  if ``risk_level`` is supplied to :meth:`PolicyEngine.evaluate`, the rule's
  declared ``risk_level`` matches as well. When the caller does not provide
  a risk level, the rule's risk level is ignored for matching purposes.
* The ``conditions`` dict allows additional structural matching against the
  invocation parameters. Each key/value pair in ``conditions`` must be
  present in ``params`` with an equal value.
* Compiled regex patterns are cached on the engine instance so repeated
  evaluations stay cheap.

Default decisions (when no rule matches) follow a conservative deny-bias:

* ``high`` risk     → :data:`PolicyDecision.DENY`
* ``medium`` risk   → :data:`PolicyDecision.REQUIRE_REVIEW`
* ``low`` / unknown → :data:`PolicyDecision.APPROVE`

Configuration:

* ``FORGE_GOVERNANCE_RULES`` — path to a JSON file containing an array of
  rule dicts. Used by :meth:`PolicyEngine.from_env`.

Requirements: 8.3.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

from forge.audit.models import AuditEntry, AuditEventType
from forge.config import PlatformSettings
from forge.core.errors import GovernanceDeniedError

if TYPE_CHECKING:
    from forge.audit.logger import AuditLogger

__all__ = [
    "PolicyDecision",
    "PolicyEngine",
    "PolicyRule",
]

_LOG = logging.getLogger(__name__)

_RiskLevel = Literal["high", "medium", "low"]
_Action = Literal["approve", "deny", "require_review"]


class PolicyDecision(str, Enum):
    """Outcome of a policy evaluation."""

    APPROVE = "approve"
    DENY = "deny"
    REQUIRE_REVIEW = "require_review"


_ACTION_TO_DECISION: dict[str, PolicyDecision] = {
    "approve": PolicyDecision.APPROVE,
    "deny": PolicyDecision.DENY,
    "require_review": PolicyDecision.REQUIRE_REVIEW,
}


class PolicyRule(BaseModel):
    """Single governance rule.

    Attributes:
        tool_pattern: Regex string matched against the invoked tool name.
        risk_level: Declared risk classification — ``"high"``, ``"medium"``,
            or ``"low"``.
        action: Action to take when the rule matches — ``"approve"``,
            ``"deny"``, or ``"require_review"``.
        conditions: Optional additional matching criteria. Each key/value
            pair must be present in the invocation ``params`` with an
            equal value for the rule to match.
    """

    tool_pattern: str
    risk_level: _RiskLevel
    action: _Action
    conditions: dict[str, object] = Field(default_factory=dict)


class PolicyEngine:
    """Evaluates tool invocations against an ordered list of :class:`PolicyRule`.

    Args:
        rules: Ordered list of policy rules. First matching rule wins.
        audit_logger: Optional audit logger that receives a
            ``GOVERNANCE_DECISION`` :class:`AuditEntry` for every
            evaluation.
    """

    def __init__(
        self,
        rules: list[PolicyRule],
        audit_logger: "AuditLogger | None" = None,
    ) -> None:
        self.rules: list[PolicyRule] = list(rules)
        self.audit_logger = audit_logger

        # Pre-compile regex patterns once. Invalid patterns are skipped
        # with a warning so a single bad rule does not disable the engine.
        self._compiled: list[tuple[re.Pattern[str], PolicyRule] | None] = []
        for rule in self.rules:
            try:
                self._compiled.append((re.compile(rule.tool_pattern), rule))
            except re.error as exc:
                _LOG.warning(
                    "PolicyEngine: ignoring rule with invalid regex %r: %s",
                    rule.tool_pattern,
                    exc,
                )
                self._compiled.append(None)
        # P2-6: hold strong refs to fire-and-forget audit tasks.
        self._pending_audit_tasks: set[asyncio.Task[None]] = set()

    # ------------------------------------------------------------------ ctor
    @classmethod
    def from_file(
        cls,
        path: str | Path,
        audit_logger: "AuditLogger | None" = None,
    ) -> "PolicyEngine":
        """Load rules from a JSON file containing an array of rule dicts.

        The file must decode to a JSON array; each element is parsed as a
        :class:`PolicyRule`. Pydantic validation errors propagate to the
        caller so misconfigured files fail loud.
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError(
                f"Governance rules file {path!s} must contain a JSON array, "
                f"got {type(data).__name__}"
            )
        rules = [PolicyRule(**entry) for entry in data]
        return cls(rules, audit_logger=audit_logger)

    @classmethod
    def from_env(
        cls,
        audit_logger: "AuditLogger | None" = None,
    ) -> "PolicyEngine":
        """Build a :class:`PolicyEngine` from ``FORGE_GOVERNANCE_RULES``.

        When the environment variable is unset, an engine with no rules is
        returned — every evaluation will fall through to the default
        decision based on ``risk_level``.
        """
        settings = PlatformSettings()
        path = settings.governance_rules
        if not path:
            return cls([], audit_logger=audit_logger)
        return cls.from_file(path, audit_logger=audit_logger)

    # ---------------------------------------------------------------- public
    def evaluate(
        self,
        tool_name: str,
        params: dict[str, object],
        risk_level: str | None = None,
        correlation_id: str | None = None,
    ) -> PolicyDecision:
        """Return the :class:`PolicyDecision` for *tool_name*.

        Rules are evaluated in declaration order; the first match wins.
        When no rule matches, the default decision is derived from
        ``risk_level``:

        * ``"high"``   → :data:`PolicyDecision.DENY`
        * ``"medium"`` → :data:`PolicyDecision.REQUIRE_REVIEW`
        * anything else → :data:`PolicyDecision.APPROVE`

        Audit entries are emitted via fire-and-forget
        :func:`asyncio.create_task` when called from inside an event loop,
        otherwise via :func:`asyncio.run`.
        """
        decision, matched_rule = self._decide(tool_name, params, risk_level)
        self._emit_decision(
            tool_name=tool_name,
            params=params,
            decision=decision,
            matched_rule=matched_rule,
            risk_level=risk_level,
            correlation_id=correlation_id,
        )
        return decision

    async def evaluate_or_raise(
        self,
        tool_name: str,
        params: dict[str, object],
        risk_level: str | None = None,
        correlation_id: str | None = None,
    ) -> PolicyDecision:
        """Evaluate and raise :class:`GovernanceDeniedError` on ``DENY``.

        Returns the decision unchanged for ``APPROVE`` and
        ``REQUIRE_REVIEW`` so callers can branch on the result.
        """
        decision = self.evaluate(
            tool_name=tool_name,
            params=params,
            risk_level=risk_level,
            correlation_id=correlation_id,
        )
        if decision is PolicyDecision.DENY:
            raise GovernanceDeniedError(
                f"Governance policy denied tool {tool_name!r} "
                f"(risk_level={risk_level!r})"
            )
        return decision

    # ------------------------------------------------------------- internals
    def _decide(
        self,
        tool_name: str,
        params: dict[str, object],
        risk_level: str | None,
    ) -> tuple[PolicyDecision, PolicyRule | None]:
        """Resolve the matching rule (or default) for the invocation."""
        for compiled in self._compiled:
            if compiled is None:
                continue
            pattern, rule = compiled
            if not pattern.search(tool_name):
                continue
            if risk_level is not None and rule.risk_level != risk_level:
                continue
            if not _conditions_satisfied(rule.conditions, params):
                continue
            return _ACTION_TO_DECISION[rule.action], rule

        # No rule matched — fall back to the risk-level default.
        return _default_decision(risk_level), None

    def _emit_decision(
        self,
        *,
        tool_name: str,
        params: dict[str, object],
        decision: PolicyDecision,
        matched_rule: PolicyRule | None,
        risk_level: str | None,
        correlation_id: str | None,
    ) -> None:
        if self.audit_logger is None:
            return
        summary = (
            f"governance_decision: {decision.value} tool={tool_name!r} "
            f"risk_level={risk_level!r} "
            f"matched_rule={matched_rule.tool_pattern if matched_rule else None!r}"
        )
        entry = AuditEntry(
            correlation_id=correlation_id or str(uuid.uuid4()),
            event_type=AuditEventType.GOVERNANCE_DECISION,
            tool_name=tool_name,
            input_params=dict(params),
            output_summary=summary,
            success=decision is not PolicyDecision.DENY,
            error_detail=(
                "policy_denied" if decision is PolicyDecision.DENY else None
            ),
        )
        coro = self.audit_logger.log(entry)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(coro)
        else:
            task = loop.create_task(coro)
            self._pending_audit_tasks.add(task)
            task.add_done_callback(self._pending_audit_tasks.discard)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _default_decision(risk_level: str | None) -> PolicyDecision:
    """Conservative default when no rule matches an invocation."""
    if risk_level == "high":
        return PolicyDecision.DENY
    if risk_level == "medium":
        return PolicyDecision.REQUIRE_REVIEW
    return PolicyDecision.APPROVE


def _conditions_satisfied(
    conditions: dict[str, object], params: dict[str, object]
) -> bool:
    """Return True iff every key/value in *conditions* matches *params*."""
    if not conditions:
        return True
    for key, expected in conditions.items():
        if key not in params or params[key] != expected:
            return False
    return True
