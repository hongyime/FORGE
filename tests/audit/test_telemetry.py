"""
tests/audit/test_telemetry.py — Unit tests for the telemetry module.

Validates:
  - Latency metrics collection for all three categories (Requirement 7.4)
  - Warning event emission when threshold is exceeded (Requirement 7.5)
  - Context manager measurement
  - Metric aggregation helpers
"""

from __future__ import annotations

import asyncio

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.audit.telemetry import (
    LatencyRecord,
    MetricCategory,
    TelemetryCollector,
)


@pytest.fixture
def audit_logger() -> AuditLogger:
    """Provide a fresh AuditLogger instance."""
    return AuditLogger()


@pytest.fixture
def telemetry(audit_logger: AuditLogger) -> TelemetryCollector:
    """Provide a TelemetryCollector with a low threshold for testing."""
    return TelemetryCollector(threshold_ms=100, audit_logger=audit_logger)


class TestLatencyRecording:
    """Verify basic latency recording for all metric categories."""

    @pytest.mark.asyncio
    async def test_record_agent_processing_latency(
        self, telemetry: TelemetryCollector
    ) -> None:
        """Agent processing time is recorded correctly."""
        record = await telemetry.record_latency(
            category=MetricCategory.AGENT_PROCESSING,
            label="discovery",
            duration_ms=50.0,
            correlation_id="corr-001",
        )

        assert record.category == MetricCategory.AGENT_PROCESSING
        assert record.label == "discovery"
        assert record.duration_ms == 50.0
        assert record.correlation_id == "corr-001"
        assert len(telemetry.records) == 1

    @pytest.mark.asyncio
    async def test_record_llm_inference_latency(
        self, telemetry: TelemetryCollector
    ) -> None:
        """LLM inference time is recorded correctly."""
        record = await telemetry.record_latency(
            category=MetricCategory.LLM_INFERENCE,
            label="llama_cpp",
            duration_ms=2500.0,
        )

        assert record.category == MetricCategory.LLM_INFERENCE
        assert record.label == "llama_cpp"
        assert record.duration_ms == 2500.0

    @pytest.mark.asyncio
    async def test_record_tool_execution_latency(
        self, telemetry: TelemetryCollector
    ) -> None:
        """Tool execution time is recorded correctly."""
        record = await telemetry.record_latency(
            category=MetricCategory.TOOL_EXECUTION,
            label="nmap_scan",
            duration_ms=8000.0,
        )

        assert record.category == MetricCategory.TOOL_EXECUTION
        assert record.label == "nmap_scan"
        assert record.duration_ms == 8000.0

    @pytest.mark.asyncio
    async def test_multiple_records_accumulated(
        self, telemetry: TelemetryCollector
    ) -> None:
        """Multiple records are accumulated in order."""
        await telemetry.record_latency(MetricCategory.AGENT_PROCESSING, "a", 10.0)
        await telemetry.record_latency(MetricCategory.LLM_INFERENCE, "b", 20.0)
        await telemetry.record_latency(MetricCategory.TOOL_EXECUTION, "c", 30.0)

        assert len(telemetry.records) == 3
        assert telemetry.records[0].label == "a"
        assert telemetry.records[1].label == "b"
        assert telemetry.records[2].label == "c"


class TestThresholdWarnings:
    """Verify warning events are emitted when latency exceeds threshold."""

    @pytest.mark.asyncio
    async def test_no_warning_below_threshold(
        self, telemetry: TelemetryCollector, audit_logger: AuditLogger
    ) -> None:
        """No warning emitted when latency is below threshold."""
        await telemetry.record_latency(
            MetricCategory.AGENT_PROCESSING, "fast_agent", 50.0
        )

        # No WARNING entries in audit log
        warning_entries = [
            e for e in audit_logger.entries if e.event_type == AuditEventType.WARNING
        ]
        assert len(warning_entries) == 0

    @pytest.mark.asyncio
    async def test_warning_emitted_above_threshold(
        self, telemetry: TelemetryCollector, audit_logger: AuditLogger
    ) -> None:
        """Warning emitted when latency exceeds threshold (Requirement 7.5)."""
        await telemetry.record_latency(
            MetricCategory.AGENT_PROCESSING,
            "slow_agent",
            150.0,  # exceeds 100ms threshold
            correlation_id="corr-slow",
        )

        warning_entries = [
            e for e in audit_logger.entries if e.event_type == AuditEventType.WARNING
        ]
        assert len(warning_entries) == 1
        entry = warning_entries[0]
        assert entry.correlation_id == "corr-slow"
        assert entry.duration_ms == 150.0
        assert "slow_agent" in (entry.output_summary or "")
        assert "threshold" in (entry.output_summary or "").lower()

    @pytest.mark.asyncio
    async def test_warning_for_tool_execution(
        self, telemetry: TelemetryCollector, audit_logger: AuditLogger
    ) -> None:
        """Warning for tool execution includes tool_name."""
        await telemetry.record_latency(
            MetricCategory.TOOL_EXECUTION, "slow_scanner", 200.0
        )

        warning_entries = [
            e for e in audit_logger.entries if e.event_type == AuditEventType.WARNING
        ]
        assert len(warning_entries) == 1
        assert warning_entries[0].tool_name == "slow_scanner"

    @pytest.mark.asyncio
    async def test_warning_for_agent_processing(
        self, telemetry: TelemetryCollector, audit_logger: AuditLogger
    ) -> None:
        """Warning for agent processing includes agent_role."""
        await telemetry.record_latency(
            MetricCategory.AGENT_PROCESSING, "analysis", 200.0
        )

        warning_entries = [
            e for e in audit_logger.entries if e.event_type == AuditEventType.WARNING
        ]
        assert len(warning_entries) == 1
        assert warning_entries[0].agent_role == "analysis"

    @pytest.mark.asyncio
    async def test_no_warning_at_exact_threshold(
        self, telemetry: TelemetryCollector, audit_logger: AuditLogger
    ) -> None:
        """No warning when latency equals threshold exactly (only exceeds)."""
        await telemetry.record_latency(
            MetricCategory.LLM_INFERENCE, "exact", 100.0
        )

        warning_entries = [
            e for e in audit_logger.entries if e.event_type == AuditEventType.WARNING
        ]
        assert len(warning_entries) == 0

    @pytest.mark.asyncio
    async def test_warning_without_audit_logger(self) -> None:
        """Warning is logged via Python logging when no audit logger configured."""
        collector = TelemetryCollector(threshold_ms=100, audit_logger=None)

        # Should not raise even without audit logger
        await collector.record_latency(
            MetricCategory.TOOL_EXECUTION, "orphan_tool", 500.0
        )

        assert len(collector.records) == 1


class TestMeasureContextManager:
    """Verify the async context manager for automatic measurement."""

    @pytest.mark.asyncio
    async def test_measure_records_elapsed_time(
        self, telemetry: TelemetryCollector
    ) -> None:
        """Context manager records elapsed time automatically."""
        async with telemetry.measure(
            MetricCategory.TOOL_EXECUTION, "sleep_tool", correlation_id="corr-m"
        ):
            await asyncio.sleep(0.05)  # 50ms

        assert len(telemetry.records) == 1
        record = telemetry.records[0]
        assert record.category == MetricCategory.TOOL_EXECUTION
        assert record.label == "sleep_tool"
        assert record.correlation_id == "corr-m"
        # Should be at least 40ms (allowing for timing variance)
        assert record.duration_ms >= 40.0

    @pytest.mark.asyncio
    async def test_measure_records_on_exception(
        self, telemetry: TelemetryCollector
    ) -> None:
        """Context manager records latency even if the body raises."""
        with pytest.raises(ValueError, match="test error"):
            async with telemetry.measure(
                MetricCategory.AGENT_PROCESSING, "failing_agent"
            ):
                raise ValueError("test error")

        # Record should still be captured
        assert len(telemetry.records) == 1
        assert telemetry.records[0].label == "failing_agent"

    @pytest.mark.asyncio
    async def test_measure_triggers_warning_on_slow_operation(
        self, telemetry: TelemetryCollector, audit_logger: AuditLogger
    ) -> None:
        """Context manager triggers warning if operation exceeds threshold."""
        async with telemetry.measure(
            MetricCategory.LLM_INFERENCE, "slow_llm"
        ):
            await asyncio.sleep(0.15)  # 150ms > 100ms threshold

        warning_entries = [
            e for e in audit_logger.entries if e.event_type == AuditEventType.WARNING
        ]
        assert len(warning_entries) == 1


class TestMetricAggregation:
    """Verify metric aggregation helper methods."""

    @pytest.mark.asyncio
    async def test_get_records_by_category(
        self, telemetry: TelemetryCollector
    ) -> None:
        """Filter records by category."""
        await telemetry.record_latency(MetricCategory.AGENT_PROCESSING, "a", 10.0)
        await telemetry.record_latency(MetricCategory.LLM_INFERENCE, "b", 20.0)
        await telemetry.record_latency(MetricCategory.AGENT_PROCESSING, "c", 30.0)

        agent_records = telemetry.get_records_by_category(
            MetricCategory.AGENT_PROCESSING
        )
        assert len(agent_records) == 2
        assert all(r.category == MetricCategory.AGENT_PROCESSING for r in agent_records)

    @pytest.mark.asyncio
    async def test_get_average_latency(
        self, telemetry: TelemetryCollector
    ) -> None:
        """Average latency is calculated correctly."""
        await telemetry.record_latency(MetricCategory.TOOL_EXECUTION, "a", 10.0)
        await telemetry.record_latency(MetricCategory.TOOL_EXECUTION, "b", 30.0)

        avg = telemetry.get_average_latency(MetricCategory.TOOL_EXECUTION)
        assert avg == 20.0

    @pytest.mark.asyncio
    async def test_get_average_latency_empty(
        self, telemetry: TelemetryCollector
    ) -> None:
        """Average latency returns None when no records exist."""
        avg = telemetry.get_average_latency(MetricCategory.LLM_INFERENCE)
        assert avg is None

    @pytest.mark.asyncio
    async def test_get_max_latency(
        self, telemetry: TelemetryCollector
    ) -> None:
        """Max latency is calculated correctly."""
        await telemetry.record_latency(MetricCategory.TOOL_EXECUTION, "a", 10.0)
        await telemetry.record_latency(MetricCategory.TOOL_EXECUTION, "b", 50.0)
        await telemetry.record_latency(MetricCategory.TOOL_EXECUTION, "c", 30.0)

        max_val = telemetry.get_max_latency(MetricCategory.TOOL_EXECUTION)
        assert max_val == 50.0

    @pytest.mark.asyncio
    async def test_get_max_latency_empty(
        self, telemetry: TelemetryCollector
    ) -> None:
        """Max latency returns None when no records exist."""
        max_val = telemetry.get_max_latency(MetricCategory.AGENT_PROCESSING)
        assert max_val is None

    @pytest.mark.asyncio
    async def test_get_threshold_violations(
        self, telemetry: TelemetryCollector
    ) -> None:
        """Threshold violations are tracked correctly."""
        await telemetry.record_latency(MetricCategory.AGENT_PROCESSING, "fast", 50.0)
        await telemetry.record_latency(MetricCategory.LLM_INFERENCE, "slow", 200.0)
        await telemetry.record_latency(MetricCategory.TOOL_EXECUTION, "medium", 80.0)
        await telemetry.record_latency(MetricCategory.TOOL_EXECUTION, "very_slow", 500.0)

        violations = telemetry.get_threshold_violations()
        assert len(violations) == 2
        labels = {v.label for v in violations}
        assert labels == {"slow", "very_slow"}


class TestTelemetryDefaults:
    """Verify default configuration behavior."""

    def test_default_threshold(self) -> None:
        """Default threshold is 5000ms per FORGE_TELEMETRY_THRESHOLD_MS."""
        collector = TelemetryCollector()
        assert collector.threshold_ms == 5000

    def test_custom_threshold(self) -> None:
        """Threshold can be configured."""
        collector = TelemetryCollector(threshold_ms=1000)
        assert collector.threshold_ms == 1000

    def test_records_start_empty(self) -> None:
        """No records exist initially."""
        collector = TelemetryCollector()
        assert collector.records == []
