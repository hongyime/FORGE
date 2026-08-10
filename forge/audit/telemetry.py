"""
forge/audit/telemetry.py — Latency metrics collection and threshold alerts.

Tracks agent processing time, LLM inference time, and tool execution time.
Emits warning events to the audit log when processing latency exceeds the
configured FORGE_TELEMETRY_THRESHOLD_MS threshold.

Requirements: 7.4, 7.5
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType

_LOG = logging.getLogger(__name__)


class MetricCategory(str, Enum):
    """Categories of latency metrics tracked by the telemetry module."""

    AGENT_PROCESSING = "agent_processing"
    LLM_INFERENCE = "llm_inference"
    TOOL_EXECUTION = "tool_execution"


@dataclass
class LatencyRecord:
    """A single latency measurement."""

    category: MetricCategory
    label: str
    duration_ms: float
    timestamp_utc: float = field(default_factory=time.time)
    correlation_id: str | None = None


class TelemetryCollector:
    """Collects latency metrics and emits warnings when thresholds are exceeded.

    The collector tracks three categories of latency:
      - Agent processing time: time spent in agent message handling
      - LLM inference time: time spent waiting for LLM provider responses
      - Tool execution time: time spent executing plugin tools

    When any measurement exceeds the configured threshold, a WARNING audit
    entry is emitted to the audit logger (Requirement 7.5).

    Attributes:
        threshold_ms: Latency threshold in milliseconds. Measurements exceeding
            this value trigger a warning event.
        audit_logger: The audit logger instance for emitting warning events.
    """

    def __init__(
        self,
        threshold_ms: int = 5000,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        """Initialize the telemetry collector.

        Args:
            threshold_ms: Latency warning threshold in milliseconds.
                Defaults to 5000ms (from FORGE_TELEMETRY_THRESHOLD_MS).
            audit_logger: Optional audit logger for emitting warning events.
                If None, warnings are only logged via Python logging.
        """
        self.threshold_ms = threshold_ms
        self.audit_logger = audit_logger
        self._records: list[LatencyRecord] = []

    @property
    def records(self) -> list[LatencyRecord]:
        """Read-only access to collected latency records."""
        return list(self._records)

    def get_records_by_category(self, category: MetricCategory) -> list[LatencyRecord]:
        """Return all records for a specific metric category."""
        return [r for r in self._records if r.category == category]

    async def record_latency(
        self,
        category: MetricCategory,
        label: str,
        duration_ms: float,
        correlation_id: str | None = None,
    ) -> LatencyRecord:
        """Record a latency measurement and emit warning if threshold exceeded.

        Args:
            category: The type of operation being measured.
            label: Human-readable label for the operation (e.g., agent role,
                tool name, provider name).
            duration_ms: The measured duration in milliseconds.
            correlation_id: Optional correlation ID linking to a workflow.

        Returns:
            The recorded LatencyRecord.
        """
        record = LatencyRecord(
            category=category,
            label=label,
            duration_ms=duration_ms,
            correlation_id=correlation_id,
        )
        self._records.append(record)

        if duration_ms > self.threshold_ms:
            await self._emit_warning(record)

        return record

    @asynccontextmanager
    async def measure(
        self,
        category: MetricCategory,
        label: str,
        correlation_id: str | None = None,
    ) -> AsyncIterator[None]:
        """Context manager that automatically measures and records latency.

        Usage::

            async with telemetry.measure(MetricCategory.TOOL_EXECUTION, "nmap_scan"):
                await run_nmap(target)

        Args:
            category: The type of operation being measured.
            label: Human-readable label for the operation.
            correlation_id: Optional correlation ID linking to a workflow.
        """
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            await self.record_latency(category, label, elapsed_ms, correlation_id)

    async def _emit_warning(self, record: LatencyRecord) -> None:
        """Emit a warning event when latency exceeds threshold.

        Logs via Python logging and, if an audit logger is configured,
        writes a WARNING audit entry (Requirement 7.5).
        """
        warning_msg = (
            f"Latency threshold exceeded: {record.category.value} "
            f"'{record.label}' took {record.duration_ms:.1f}ms "
            f"(threshold: {self.threshold_ms}ms)"
        )
        _LOG.warning(warning_msg)

        if self.audit_logger is not None:
            entry = AuditEntry(
                correlation_id=record.correlation_id or "telemetry",
                event_type=AuditEventType.WARNING,
                tool_name=record.label
                if record.category == MetricCategory.TOOL_EXECUTION
                else None,
                agent_role=record.label
                if record.category == MetricCategory.AGENT_PROCESSING
                else None,
                output_summary=warning_msg,
                duration_ms=record.duration_ms,
                success=True,
            )
            await self.audit_logger.log(entry)

    def get_average_latency(self, category: MetricCategory) -> float | None:
        """Calculate average latency for a given category.

        Returns None if no records exist for the category.
        """
        records = self.get_records_by_category(category)
        if not records:
            return None
        return sum(r.duration_ms for r in records) / len(records)

    def get_max_latency(self, category: MetricCategory) -> float | None:
        """Get the maximum latency recorded for a given category.

        Returns None if no records exist for the category.
        """
        records = self.get_records_by_category(category)
        if not records:
            return None
        return max(r.duration_ms for r in records)

    def get_threshold_violations(self) -> list[LatencyRecord]:
        """Return all records that exceeded the configured threshold."""
        return [r for r in self._records if r.duration_ms > self.threshold_ms]
