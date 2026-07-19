"""
forge/phase6/llm_validator.py

Phase 6 — LLM Output Quality Gate.

Validates raw LLM report text against a rule set before the report is
written to disk or delivered to a client. Validation is purely rule-based
(regex + structural checks); no LLM round-trip is used for validation.

Validation rules:
  V-01  All mandatory sections present
  V-02  Overall risk label present in Executive Summary
  V-03  No internal RFC-1918 IP addresses in generated prose
  V-04  No plaintext credential patterns (password=, api_key=, etc.)
  V-05  Minimum section length (≥50 words each mandatory section)
  V-06  Executive Summary ≤ 500 words (avoids LLM padding)
  V-07  No paste URLs in report body
  V-08  No raw CVE exploit payloads (shellcode, msfvenom patterns)
  V-09  No evidence strings > 512 chars (passed through from DB)
  V-10  If Ongoing Intelligence present, Exec Summary references monitoring

Severity levels: ERROR (blocks delivery), WARNING (advisory).
Strict mode: --strict promotes all WARNINGs to ERRORs.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forge.phase6.report_synthesizer import OngoingIntelligenceContext

logger = logging.getLogger(__name__)

# ── Patterns ───────────────────────────────────────────────────────────────────

_RFC1918_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b",
)

_CRED_LEAK_RE = re.compile(
    r"(?:password|passwd|api[_-]?key|secret|token)\s*[=:]\s*\S+",
    re.IGNORECASE,
)

_PASTE_URL_RE = re.compile(
    r"https?://(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.co|privatebin\.net)/\S+",
    re.IGNORECASE,
)

_SHELLCODE_RE = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}){8,}"      # 8+ consecutive \xNN escape sequences
    r"|msfvenom\b"
    r"|meterpreter\b",
    re.IGNORECASE,
)

_MONITORING_KEYWORDS = frozenset({
    "monitoring", "ongoing", "intelligence", "paste", "post-engagement",
    "leaklooker", "exfil monitor",
})

RISK_LABELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}


# ── Result model ───────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    """
    Outcome of validate_report().

    Attributes:
        passed:   True when errors is empty (warnings do not block delivery).
        errors:   List of blocking rule violations (must be fixed before delivery).
        warnings: List of advisory issues (noted in audit log; do not block).
    """
    errors:   list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    def summary(self) -> str:
        if self.passed:
            return (
                f"PASSED — {len(self.warnings)} warning(s)."
                if self.warnings
                else "PASSED — clean."
            )
        return (
            f"FAILED — {len(self.errors)} error(s), "
            f"{len(self.warnings)} warning(s)."
        )


# ── Individual rule implementations ────────────────────────────────────────────

def _v01_mandatory_sections(
    text: str, result: ValidationResult, strict: bool
) -> None:
    """V-01: All mandatory sections must be present."""
    from forge.phase6.report_synthesizer import MANDATORY_SECTIONS
    for section in MANDATORY_SECTIONS:
        if section not in text:
            result.errors.append(
                f"[V-01] Mandatory section missing: {section!r}."
            )


def _v02_risk_label_in_exec_summary(
    text: str, overall_risk: str, result: ValidationResult, strict: bool
) -> None:
    """V-02: Risk label must appear in Executive Summary prose."""
    exec_match = re.search(
        r"## 1\. Executive Summary\n(.*?)(?=\n## |\Z)", text, re.DOTALL
    )
    if not exec_match:
        return   # V-01 already raised; skip
    exec_text = exec_match.group(1)
    if overall_risk.upper() not in exec_text.upper():
        msg = (
            f"[V-02] Overall risk label '{overall_risk}' not found in "
            "Executive Summary. The LLM must state the risk level explicitly."
        )
        result.errors.append(msg)


def _v03_no_internal_ips(
    text: str, approved_ips: list[str] | None,
    result: ValidationResult, strict: bool
) -> None:
    """
    V-03: RFC-1918 addresses in prose are suspicious in client reports.
    IPs in scope or header blocks are exempt. Others are flagged.
    """
    approved = set(approved_ips or [])
    for match in _RFC1918_RE.finditer(text):
        ip = match.group()
        if ip in approved:
            continue
        msg = (
            f"[V-03] Internal IP {ip!r} found in report body. "
            "Reference targets by hostname or role only."
        )
        if strict:
            result.errors.append(msg)
        else:
            result.warnings.append(msg)
            logger.warning(msg)


def _v04_no_credential_leaks(
    text: str, result: ValidationResult, strict: bool
) -> None:
    """V-04: No plaintext credential patterns in report body."""
    match = _CRED_LEAK_RE.search(text)
    if match:
        result.errors.append(
            f"[V-04] Credential leak pattern detected: {match.group()!r}. "
            "Credentials must never appear in client-deliverable reports."
        )


def _v05_minimum_section_length(
    text: str, result: ValidationResult, strict: bool
) -> None:
    """V-05: Each mandatory section must contain ≥50 words of prose."""
    from forge.phase6.report_synthesizer import MANDATORY_SECTIONS
    for section in MANDATORY_SECTIONS:
        idx = text.find(section)
        if idx == -1:
            continue  # V-01 handles missing sections
        # Find start of next section
        next_section_idx = len(text)
        for other in MANDATORY_SECTIONS:
            if other == section:
                continue
            other_idx = text.find(other, idx + 1)
            if other_idx != -1 and other_idx < next_section_idx:
                next_section_idx = other_idx
        section_body = text[idx + len(section):next_section_idx]
        word_count   = len(section_body.split())
        if word_count < 50:
            msg = (
                f"[V-05] Section {section!r} has only {word_count} words "
                "(minimum 50). LLM may have truncated its output."
            )
            if strict:
                result.errors.append(msg)
            else:
                result.warnings.append(msg)
                logger.warning(msg)


def _v06_exec_summary_word_cap(
    text: str, result: ValidationResult, strict: bool
) -> None:
    """V-06: Executive Summary must not exceed 500 words (avoids LLM padding)."""
    exec_match = re.search(
        r"## 1\. Executive Summary\n(.*?)(?=\n## |\Z)", text, re.DOTALL
    )
    if not exec_match:
        return
    word_count = len(exec_match.group(1).split())
    if word_count > 500:
        msg = (
            f"[V-06] Executive Summary is {word_count} words (maximum 500). "
            "Trim or regenerate the section."
        )
        if strict:
            result.errors.append(msg)
        else:
            result.warnings.append(msg)
            logger.warning(msg)


def _v07_no_paste_urls(
    text: str, result: ValidationResult, strict: bool
) -> None:
    """V-07: No public paste-site URLs in report body."""
    matches = _PASTE_URL_RE.findall(text)
    if matches:
        result.errors.append(
            f"[V-07] Paste URL(s) found in report: {matches[:3]}. "
            "Reference by platform and date only."
        )


def _v08_no_shellcode(
    text: str, result: ValidationResult, strict: bool
) -> None:
    """V-08: No raw shellcode sequences or msfvenom/meterpreter strings."""
    match = _SHELLCODE_RE.search(text)
    if match:
        result.errors.append(
            f"[V-08] Exploit payload pattern detected: {match.group()!r}. "
            "Reports must not contain raw shellcode or framework strings."
        )


def _v09_evidence_length(
    text: str, result: ValidationResult, strict: bool
) -> None:
    """
    V-09: No individual evidence block > 512 chars in the report.
    Evidence should be summarised, not reproduced verbatim.
    """
    evidence_blocks = re.findall(r"Evidence:(.*?)(?=\n[A-Z]|\Z)", text, re.DOTALL)
    for block in evidence_blocks:
        if len(block.strip()) > 512:
            msg = (
                f"[V-09] Evidence block exceeds 512 chars "
                f"({len(block.strip())} chars). Summarise rather than reproduce."
            )
            if strict:
                result.errors.append(msg)
            else:
                result.warnings.append(msg)
                logger.warning(msg)


def _v10_exec_summary_monitoring_reference(
    text: str,
    ongoing_intel: "OngoingIntelligenceContext",
    result: ValidationResult,
    strict: bool,
) -> None:
    """
    V-10: If Ongoing Intelligence data is present and Section 8 was rendered,
    the Executive Summary must reference the monitoring findings.
    """
    if not ongoing_intel.monitoring_enabled or ongoing_intel.new_findings_count == 0:
        return

    exec_match = re.search(
        r"## 1\. Executive Summary\n(.*?)(?=\n## |\Z)", text, re.DOTALL
    )
    if not exec_match:
        return   # V-01 already covers missing section

    exec_text = exec_match.group(1).lower()
    has_reference = any(kw in exec_text for kw in _MONITORING_KEYWORDS)

    if not has_reference:
        msg = (
            "[V-10] Ongoing Intelligence section is present but the Executive "
            "Summary contains no reference to monitoring findings. Update the "
            "Executive Summary to acknowledge post-engagement exposure."
        )
        if strict:
            result.errors.append(msg)
        else:
            result.warnings.append(msg)
            logger.warning(msg)


# ── Public API ─────────────────────────────────────────────────────────────────

def validate_report(
    raw_text:             str,
    overall_risk:         str,
    approved_internal_ips: list[str] | None = None,
    strict:               bool = False,
    ongoing_intel:        "OngoingIntelligenceContext | None" = None,
) -> ValidationResult:
    """
    Run all validation rules against a generated report.

    Args:
        raw_text:              Full Markdown text produced by the LLM.
        overall_risk:          Rule-derived overall risk label (e.g. 'HIGH').
        approved_internal_ips: IPs from engagement scope; exempt from V-03.
        strict:                Promote WARNINGs to ERRORs.
        ongoing_intel:         OngoingIntelligenceContext; required for V-10.

    Returns:
        ValidationResult with .passed, .errors, .warnings.
    """
    result = ValidationResult()

    _v01_mandatory_sections(raw_text, result, strict)
    _v02_risk_label_in_exec_summary(raw_text, overall_risk, result, strict)
    _v03_no_internal_ips(raw_text, approved_internal_ips, result, strict)
    _v04_no_credential_leaks(raw_text, result, strict)
    _v05_minimum_section_length(raw_text, result, strict)
    _v06_exec_summary_word_cap(raw_text, result, strict)
    _v07_no_paste_urls(raw_text, result, strict)
    _v08_no_shellcode(raw_text, result, strict)
    _v09_evidence_length(raw_text, result, strict)

    if ongoing_intel is not None:
        _v10_exec_summary_monitoring_reference(raw_text, ongoing_intel, result, strict)

    logger.info("Validation: %s", result.summary())
    return result
