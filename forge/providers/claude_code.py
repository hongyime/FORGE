"""
forge/providers/claude_code.py - Subprocess shell-out to Claude Code CLI.

Runs ``claude --print "<prompt>"``, captures stdout as the completion
text. Uses the operator's existing Claude Code subscription / OAuth - no
API key needed.

Detection: ``claude`` binary present on PATH AND ``~/.claude.json``
contains a populated ``oauthAccount`` (i.e. user has logged in).

Implementation: thin subclass of :class:`SubprocessProvider` so all three
CLI shell-out providers (``claude_code``, ``codex_cli``, ``gemini_cli``)
share the same timeout / process / error handling.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from pathlib import Path

from forge.providers._subprocess_base import SubprocessProvider

__all__ = ["ClaudeCodeProvider", "claude_code_available"]

_LOG = logging.getLogger(__name__)


def claude_code_available() -> tuple[bool, str | None]:
    bin_path = shutil.which("claude") or shutil.which("claude.cmd")
    if not bin_path:
        return False, None
    cfg = Path(os.path.expanduser("~/.claude.json"))
    if not cfg.exists():
        return False, None
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False, None
    oauth = data.get("oauthAccount")
    if not isinstance(oauth, dict) or not oauth.get("accountUuid"):
        return False, None
    return True, "claude-code-subscription"


class ClaudeCodeProvider(SubprocessProvider):
    backend_name = "claude_code"
    default_model_id = "claude-code-subscription"
    completion_args = ("--print",)
    version_args = ("--version",)

    def __init__(
        self,
        *,
        binary: str = "claude",
        timeout: float = 120.0,
        model_id: str = "claude-code-subscription",
    ) -> None:
        super().__init__(binary=binary, timeout=timeout, model_id=model_id)