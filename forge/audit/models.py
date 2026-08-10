"""
forge/audit/models.py - Audit entry models and event types.

Defines the AuditEntry Pydantic model and AuditEventType enum used
throughout the platform for append-only audit logging.

Hardening (2026-05-26):
  * Added ``sequence_number`` field driven by an itertools.count() so
    AuditEntry instances are strictly orderable even when ``time.time()``
    is non-monotonic (NTP skew, clock adjustments).
  * Added Pydantic length validators on string fields to reject
    pathological inputs (a 100MB ``correlation_id`` would otherwise
    OOM the process).
  * Added MAX_INPUT_PARAMS_BYTES guard on the JSON-serialised payload
    so a single bad caller cannot wedge the audit pipeline.

Requirements: 7.1, 7.2, 7.3
"""

from __future__ import annotations

import itertools
import json
import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

__all__ = [
    "MAX_AGENT_ROLE_LEN",
    "MAX_CORRELATION_ID_LEN",
    "MAX_ERROR_DETAIL_LEN",
    "MAX_INPUT_PARAMS_BYTES",
    "MAX_OUTPUT_SUMMARY_LEN",
    "MAX_TOOL_NAME_LEN",
    "AuditEntry",
    "AuditEventType",
]

# ---------------------------------------------------------------------------
# Bounds (P1-4 hardening)
# ---------------------------------------------------------------------------

#: Maximum bytes any AuditEntry's input_params dict may serialise to.
MAX_INPUT_PARAMS_BYTES: int = 256 * 1024  # 256 KB

#: Maximum length of correlation_id strings.
MAX_CORRELATION_ID_LEN: int = 256

#: Maximum length of agent_role / tool_name identifiers.
MAX_AGENT_ROLE_LEN: int = 128
MAX_TOOL_NAME_LEN: int = 128

#: Maximum length of free-form summary / detail strings.
MAX_OUTPUT_SUMMARY_LEN: int = 8 * 1024
MAX_ERROR_DETAIL_LEN: int = 16 * 1024

# ---------------------------------------------------------------------------
# Internal monotonic counter (P2-9 hardening)
# ---------------------------------------------------------------------------

# Process-local monotonic sequence; survives clock adjustments.
_SEQUENCE = itertools.count()


def _next_sequence() -> int:
    return next(_SEQUENCE)


class AuditEventType(str, Enum):
    """Classification of audit log events."""

    MESSAGE_RECEIVED = "message_received"
    TOOL_INVOCATION = "tool_invocation"
    LLM_INFERENCE = "llm_inference"
    STATE_TRANSITION = "state_transition"
    SCOPE_DECISION = "scope_decision"
    GOVERNANCE_DECISION = "governance_decision"
    ERROR = "error"
    WARNING = "warning"
    TELEMETRY_LATENCY = "telemetry_latency"


class AuditEntry(BaseModel):
    """Single audit log record.

    Attributes:
        timestamp_utc: UTC epoch seconds when the event occurred. May be
            non-monotonic; pair with ``sequence_number`` for ordering.
        sequence_number: Monotonically increasing counter assigned at
            construction time. Strictly orderable; survives clock skew.
        correlation_id: Links related events across a workflow execution.
        event_type: Classification of the event.
        agent_role: Role of the agent that generated the event.
        tool_name: Name of the tool invoked.
        input_params: Parameters passed to the tool (secrets redacted).
        output_summary: Brief summary of the tool output.
        duration_ms: Execution duration in milliseconds.
        success: Whether the operation succeeded.
        error_detail: Error message if the operation failed.
    """

    timestamp_utc: float = Field(default_factory=time.time)
    sequence_number: int = Field(default_factory=_next_sequence)
    correlation_id: str = Field(max_length=MAX_CORRELATION_ID_LEN)
    event_type: AuditEventType
    agent_role: str | None = Field(default=None, max_length=MAX_AGENT_ROLE_LEN)
    tool_name: str | None = Field(default=None, max_length=MAX_TOOL_NAME_LEN)
    input_params: dict[str, object] | None = None
    output_summary: str | None = Field(default=None, max_length=MAX_OUTPUT_SUMMARY_LEN)
    duration_ms: float | None = None
    success: bool = True
    error_detail: str | None = Field(default=None, max_length=MAX_ERROR_DETAIL_LEN)

    @field_validator("input_params")
    @classmethod
    def _input_params_size_limit(cls, v: dict[str, object] | None) -> dict[str, object] | None:
        """Reject input_params that would exceed MAX_INPUT_PARAMS_BYTES.

        Encodes via ``json.dumps(default=str)`` so non-JSON-native objects
        (datetime, Path) are coerced to strings. Raises ValueError when
        the encoded form exceeds the limit so callers see a clear
        Pydantic ValidationError instead of an unbounded write.
        """
        if v is None:
            return None
        try:
            encoded = json.dumps(v, default=str)
        except (TypeError, ValueError):
            # Non-encodable contents - return as-is and let downstream
            # serialisation surface the failure.
            return v
        if len(encoded) > MAX_INPUT_PARAMS_BYTES:
            raise ValueError(
                f"input_params encoded size ({len(encoded)} bytes) exceeds "
                f"MAX_INPUT_PARAMS_BYTES ({MAX_INPUT_PARAMS_BYTES})"
            )
        return v
