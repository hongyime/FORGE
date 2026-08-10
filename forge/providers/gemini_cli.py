"""
forge/providers/gemini_cli.py - Subprocess shell-out to Google Gemini CLI.

Runs ``gemini -p "<prompt>"`` (the ``-p`` flag is the non-interactive
prompt mode), captures stdout as the completion text. Uses the operator's
Google AI Studio subscription via the Gemini CLI's own auth - no API key
needed.

Detection: ``gemini`` binary present on PATH.

KNOWN LIMITATION (2026-07-06)
-----------------------------
Google migrated individual Gemini Code Assist accounts to a separate
product line called "Antigravity" (https://antigravity.google). The
existing ``gemini`` CLI (0.46.0) throws ``IneligibleTierError`` for
individual accounts and can only authenticate against enterprise Gemini
Code Assist tenants. For individual-tier operators this provider is
effectively blocked until Google reopens the individual CLI path.

Workaround: use ``--provider openai_compatible`` with the Google Gemini
API endpoint (https://generativelanguage.googleapis.com/v1beta/openai)
and a Gemini API key. That path bypasses the CLI-tier check.
"""

from __future__ import annotations

import logging
import shutil

from forge.providers._subprocess_base import SubprocessProvider

__all__ = ["GeminiCliProvider", "gemini_cli_available"]

_LOG = logging.getLogger(__name__)


def gemini_cli_available() -> tuple[bool, str | None]:
    """Return (available, model_id_hint) probing the local Gemini CLI install."""
    bin_path = shutil.which("gemini") or shutil.which("gemini.cmd")
    if not bin_path:
        return False, None
    return True, "gemini-3-pro-subscription"


class GeminiCliProvider(SubprocessProvider):
    """LLMProvider backed by the Google Gemini CLI."""

    backend_name = "gemini_cli"
    default_model_id = "gemini-3-pro-subscription"
    completion_args = ("-p",)
    version_args = ("--version",)

    def __init__(
        self,
        *,
        binary: str = "gemini",
        timeout: float = 180.0,
        model_id: str = "gemini-3-pro-subscription",
    ) -> None:
        super().__init__(binary=binary, timeout=timeout, model_id=model_id)

    def _extra_env(self):  # type: ignore[override]
        """Gemini CLI demands a real TTY-shape env.

        - Fatal-warns on ``TERM=dumb`` (which our --no-tor + Rich-off env
          sets during report generation). Force to a 256-color TERM.
        - Ignores ``NO_COLOR`` when ``FORCE_COLOR`` is set, so we unset
          ``FORCE_COLOR`` explicitly.
        """
        return {
            "TERM": "xterm-256color",
            "FORCE_COLOR": None,  # unset
            "NO_COLOR": "1",  # gemini honours this once FORCE_COLOR is gone
        }

    def _format_prompt(self, request):  # type: ignore[override]
        """Plain-language framing — gemini treats the input as one prompt."""
        if not request.system:
            return request.prompt
        return f"System guidance: {request.system}\n\n---\n\n{request.prompt}"
