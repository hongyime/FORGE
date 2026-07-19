"""
forge/plugins/migrated/reporting_plugins.py — Phase 6 reporting wrappers.

Adapts report synthesis and LLM validation modules to the standard
``Plugin`` protocol so the orchestrator can dispatch them through the
unified plugin executor. Both plugins are read-only and carry
``RiskLevel.LOW`` since they consume engagement data and produce reports
without modifying targets.

Requirements: 4.7, 11.4
"""

from __future__ import annotations

from forge.plugins.base import (
    ExecutionMode,
    Plugin,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)
from forge.plugins.migrated._adapter import invoke_phase

__all__ = [
    "ReportSynthesizerPlugin",
    "LlmValidatorPlugin",
    "report_synthesizer_plugin",
    "llm_validator_plugin",
]

_VERSION = "7.2.0"


class _BaseReportingPlugin:
    """Shared scaffolding for phase-6 reporting plugins."""

    _metadata: PluginMetadata
    _module_path: str
    _candidates: tuple[str, ...] = ("run", "main", "synthesize", "validate")

    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata

    async def execute(self, params: dict[str, object]) -> PluginResult:
        return await invoke_phase(
            self._module_path,
            params or {},
            candidates=self._candidates,
        )

    async def health_check(self) -> bool:
        return True


class ReportSynthesizerPlugin(_BaseReportingPlugin):
    """Wraps ``forge.phase6.report_synthesizer`` for report generation."""

    _module_path = "forge.phase6.report_synthesizer"
    _candidates = ("synthesize", "generate", "run", "main")
    _metadata = PluginMetadata(
        name="report_synthesizer",
        version=_VERSION,
        capabilities=["report"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=300,
        risk_level=RiskLevel.LOW,
        description="Synthesise an engagement report from captured findings.",
    )


class LlmValidatorPlugin(_BaseReportingPlugin):
    """Wraps ``forge.phase6.llm_validator`` for LLM-assisted validation."""

    _module_path = "forge.phase6.llm_validator"
    _candidates = ("validate", "review", "run", "main")
    _metadata = PluginMetadata(
        name="llm_validator",
        version=_VERSION,
        capabilities=["report", "query"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=300,
        risk_level=RiskLevel.LOW,
        description="LLM-assisted validation pass over synthesised findings.",
    )


report_synthesizer_plugin: Plugin = ReportSynthesizerPlugin()
llm_validator_plugin: Plugin = LlmValidatorPlugin()
