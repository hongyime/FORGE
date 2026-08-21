"""Human-facing dashboard/report display sanitizers."""
from __future__ import annotations

import re
from typing import Any

_SCOPE_MANIFEST_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(scope_manifest(?:_json|_payload)?)\b\s*[:=]\s*"
    r"(?:\{[^;]*?\}|\[[^;]*?\]|\"[^\"]*\"|'[^']*'|.*?)(?=(?:\s+[\w.-]+\s*[:=])|[,;]|$)"
)
_CLI_HELP_RE = re.compile(
    r"(?is)(?:try\s+['\"]?[^'\"]*--help['\"]?\s+for\s+help\.?|"
    r"(?:[\w.-]+\s+){0,4}--help['\"]?\s+for\s+help\.?)"
)
_RICH_BORDER_RE = re.compile(r"[\u2500-\u257f\u2580-\u259f]+")
_TERMINAL_CONTROL_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def sanitize_report_display_text(value: Any) -> str:
    """Return a bounded-safety display string without local paths or CLI noise."""

    text = str(value or "").strip()
    if not text:
        return ""
    normalized = text.lower()
    if normalized == "abandoned before explicit completion":
        text = "interrupted before finalization"
    if "gguf model not found" in normalized:
        return "GGUF model not found; configure an LLM provider/model or regenerate after local model setup."
    if "--help" in text and "error" in normalized:
        return "Command failed before completion; review the raw run log for the full CLI diagnostic."
    text = _TERMINAL_CONTROL_RE.sub("", text)
    text = _RICH_BORDER_RE.sub(" ", text)
    text = _CLI_HELP_RE.sub("CLI invocation rejected", text)
    text = _SCOPE_MANIFEST_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]",
        text,
    )
    return " ".join(text.split())
