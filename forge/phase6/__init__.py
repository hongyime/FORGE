"""
forge/phase6/__init__.py

Phase 6 — LLM-Assisted Reporting.

Public API (lazy-loaded; llama_cpp model loading is expensive and must only
occur when report generation is explicitly invoked).
"""
from __future__ import annotations


def __getattr__(name: str):
    if name == "ReportSynthesizer":
        from forge.phase6.report_synthesizer import ReportSynthesizer
        return ReportSynthesizer
    if name == "validate_report":
        from forge.phase6.llm_validator import validate_report
        return validate_report
    if name == "ValidationResult":
        from forge.phase6.llm_validator import ValidationResult
        return ValidationResult
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["ReportSynthesizer", "validate_report", "ValidationResult"]
