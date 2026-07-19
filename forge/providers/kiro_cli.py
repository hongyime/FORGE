"""
forge/providers/kiro_cli.py - Subprocess shell-out to Kiro CLI (kiro-cli).

Runs ``kiro-cli chat --no-interactive --trust-tools='' "<prompt>"`` and
captures the model response from the decorated stdout. Uses the operator's
existing Kiro subscription / model configuration - no API key needed.

Detection: ``kiro-cli`` binary present on PATH AND the operator has an
active Kiro chat session (`kiro-cli whoami` returns 0). Kiro CLI is the
same tool a developer runs interactively - forge just invokes it once,
non-interactively, per Phase 6 report.

OUTPUT PARSING
--------------
Kiro CLI decorates stdout with a banner, credits/time, and ANSI colour
codes. The actual model response follows a ``> `` prompt marker. This
provider strips ANSI codes, finds the last ``> `` occurrence, and
returns everything after it as the completion.

For any given engagement, kiro-cli's response quality is bounded by the
model the operator has configured (typically Claude Sonnet 4.x). It is
the highest-quality provider available without an API key - the natural
default when kiro-cli is on PATH.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import time
from pathlib import Path

from forge.core.errors import ProviderUnavailableError
from forge.providers._subprocess_base import SubprocessProvider
from forge.providers.base import CompletionRequest, CompletionResponse

__all__ = ["KiroCliProvider", "kiro_cli_available"]

_LOG = logging.getLogger(__name__)

# Match CSI sequences (e.g. "\x1b[31;1m") — the decorators kiro-cli emits.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


def kiro_cli_available() -> tuple[bool, str | None]:
    """Return (available, model_id_hint) probing the local Kiro CLI install."""
    bin_path = shutil.which("kiro-cli") or shutil.which("kiro-cli.exe")
    if not bin_path:
        return False, None
    return True, "kiro-cli-subscription"


def _strip_ansi(text: str) -> str:
    """Remove all ANSI CSI escape sequences from ``text``."""
    return _ANSI_RE.sub("", text)


def _extract_response(raw: str) -> str:
    """Extract the model response from kiro-cli's decorated stdout.

    Pattern: banner / credits / ``> `` prompt marker / response. We take
    everything after the last ``> `` marker and trim. If no marker is
    found (older versions), fall back to the last non-empty line group.
    """
    clean = _strip_ansi(raw).replace("\r", "")
    marker = "\n> "
    idx = clean.rfind(marker)
    if idx == -1:
        # Try without leading newline (rare)
        idx = clean.rfind("> ")
    if idx == -1:
        # Fallback: return last non-empty content
        return clean.strip()
    tail = clean[idx + len(marker):] if clean[idx:].startswith(marker) else clean[idx + 2:]
    return tail.strip()


class KiroCliProvider(SubprocessProvider):
    """LLMProvider backed by kiro-cli (Kiro CLI chat).

    Uses ``chat --no-interactive`` for one-shot request/response. Trust
    is fully locked down (``--trust-tools=''``) so the invocation cannot
    run any tools, only produce text.
    """

    backend_name = "kiro_cli"
    default_model_id = "kiro-cli-subscription"
    completion_args = ("chat", "--no-interactive", "--trust-tools=")
    version_args = ("--version",)

    def __init__(
        self,
        *,
        binary: str = "kiro-cli",
        timeout: float = 240.0,
        model_id: str = "kiro-cli-subscription",
    ) -> None:
        super().__init__(binary=binary, timeout=timeout, model_id=model_id)

    def _format_prompt(self, request):  # type: ignore[override]
        """Kiro CLI receives the prompt as one argv. Merge system + user
        naturally; the underlying model (Claude by default) handles
        role-aware framing on the server side.
        """
        if not request.system:
            return request.prompt
        return f"{request.system.rstrip()}\n\n{request.prompt.lstrip()}"

    async def complete(self, request):  # type: ignore[override]
        """Kiro-specific complete: parse decorated stdout for the response."""
        prompt = self._format_prompt(request)
        argv = [self._binary, *self.completion_args, prompt]

        env = os.environ.copy()
        for k, v in self._extra_env().items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v

        t0 = time.perf_counter()
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError as exc:
            raise ProviderUnavailableError(
                f"{self.backend_name}: binary not executable: {exc}"
            ) from exc

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=self._timeout
            )
        except asyncio.TimeoutError as exc:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise ProviderUnavailableError(
                f"{self.backend_name}: timeout after {self._timeout}s"
            ) from exc

        raw_stdout = stdout_bytes.decode("utf-8", errors="replace")
        raw_stderr = stderr_bytes.decode("utf-8", errors="replace")

        if proc.returncode != 0:
            detail = raw_stderr[:400] or raw_stdout[:400] or "<no output>"
            raise ProviderUnavailableError(
                f"{self.backend_name}: exit={proc.returncode} detail={detail!r}"
            )

        text = _extract_response(raw_stdout)
        if not text:
            raise ProviderUnavailableError(
                f"{self.backend_name}: empty response after parsing "
                f"(raw stdout len={len(raw_stdout)})"
            )
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return CompletionResponse(
            text=text,
            model_id=self._model_id,
            prompt_tokens=max(1, len(prompt) // 4),
            completion_tokens=max(1, len(text) // 4),
            latency_ms=max(0.0, latency_ms),
        )
