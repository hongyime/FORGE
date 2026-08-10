"""
forge/providers/codex_cli.py - Subprocess shell-out to OpenAI Codex CLI.

Runs ``codex exec --skip-git-repo-check --output-last-message <tmp> "<prompt>"``
non-interactively, captures the model's final message from the temp file.
Uses the operator's ChatGPT subscription via the Codex CLI's own auth - no
API key needed.

The ``--skip-git-repo-check`` flag prevents Codex from refusing to run
when forge is invoked outside a git repo. ``--output-last-message`` writes
ONLY the model's final response to the given file (stdout would otherwise
be decorated with role labels + token counts).

Detection: ``codex`` binary present on PATH.

KNOWN LIMITATION (2026-07-06)
-----------------------------
Codex CLI is designed as a code-editing / agent workflow tool. Even with
a full source-material prompt and an explicit "produce now" imperative,
it tends to respond with "send me source material" or "I'll write in that
style — what's the target?" This provider works for short one-shot
answers (verified: 17-char smoke test returned exactly ``PROVIDER_OK_CODEX``)
but is NOT recommended for long-form Phase 6 report generation. For that,
use ``--provider claude_code`` (Claude API via CLI subscription) or
``--provider openai_compatible`` with a real OpenAI/Anthropic/etc endpoint.
"""

from __future__ import annotations

import logging
import shutil

from forge.providers._subprocess_base import SubprocessProvider

__all__ = ["CodexCliProvider", "codex_cli_available"]

_LOG = logging.getLogger(__name__)


def codex_cli_available() -> tuple[bool, str | None]:
    """Return (available, model_id_hint) probing the local Codex CLI install."""
    bin_path = shutil.which("codex") or shutil.which("codex.cmd")
    if not bin_path:
        return False, None
    return True, "gpt-5-codex-subscription"


class CodexCliProvider(SubprocessProvider):
    """LLMProvider backed by the OpenAI Codex CLI."""

    backend_name = "codex_cli"
    default_model_id = "gpt-5-codex-subscription"
    # Codex prints helpful text to stderr; ``exec`` is the non-interactive
    # subcommand. ``--skip-git-repo-check`` prevents refusal when forge
    # runs outside a git checkout. ``--output-last-message`` is set at
    # call time (needs a per-invocation temp file), so it's added inside
    # ``complete()`` rather than in the class-level tuple here.
    completion_args = ("exec", "--skip-git-repo-check")
    version_args = ("--version",)

    def __init__(
        self,
        *,
        binary: str = "codex",
        timeout: float = 240.0,  # codex sessions can be slow on first call
        model_id: str = "gpt-5-codex-subscription",
    ) -> None:
        super().__init__(binary=binary, timeout=timeout, model_id=model_id)

    def _format_prompt(self, request):  # type: ignore[override]
        """Codex-CLI plain-text prompt format.

        Codex reads argv as a single imperative. Any two-turn shape (system
        directive + user task) confuses it into responding to the system
        rules ("Understood. Send the source material.") instead of doing
        the work. The report synthesizer's user prompt already contains a
        role declaration ("You are a senior pentest report writer...") plus
        source material plus an explicit "produce now" imperative, so we
        pass it through unchanged and drop the system prompt.

        If a caller sends only a system prompt (edge case), we return it
        as-is so codex has something to work with.
        """
        return request.prompt or request.system or ""

    async def complete(self, request):  # type: ignore[override]
        """Codex-specific complete: use --output-last-message for clean stdout.

        Codex's default stdout is decorated (user/codex/tokens blocks). The
        model's final response appears in both the decorated block AND on a
        line by itself, but parsing it is brittle. ``--output-last-message
        <FILE>`` writes ONLY the model's final response to the given file,
        which we then read and return. Cleaner than regex-parsing decoration.
        """
        import asyncio  # noqa: PLC0415
        import os as _os  # noqa: PLC0415
        import tempfile  # noqa: PLC0415
        import time  # noqa: PLC0415
        from pathlib import Path  # noqa: PLC0415
        from forge.core.errors import ProviderUnavailableError  # noqa: PLC0415
        from forge.providers.base import CompletionResponse  # noqa: PLC0415

        prompt = self._format_prompt(request)
        env = _os.environ.copy()
        for k, v in self._extra_env().items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v

        # Per-call temp file for the model's last message
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".txt", prefix="forge_codex_")
        _os.close(tmp_fd)
        try:
            argv = [
                self._binary,
                "exec",
                "--skip-git-repo-check",
                "--output-last-message",
                tmp_path,
                prompt,
            ]
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

            if proc.returncode != 0:
                stderr = stderr_bytes.decode("utf-8", errors="replace")[:500]
                stdout = stdout_bytes.decode("utf-8", errors="replace")[:500]
                raise ProviderUnavailableError(
                    f"{self.backend_name}: exit={proc.returncode} "
                    f"detail={(stderr or stdout or '<no output>')!r}"
                )

            text = Path(tmp_path).read_text(encoding="utf-8", errors="replace").strip()
            if not text:
                # Fallback: parse stdout tail
                text = stdout_bytes.decode("utf-8", errors="replace").strip()
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return CompletionResponse(
                text=text,
                model_id=self._model_id,
                prompt_tokens=max(1, len(prompt) // 4),
                completion_tokens=max(1, len(text) // 4),
                latency_ms=max(0.0, latency_ms),
            )
        finally:
            try:
                _os.unlink(tmp_path)
            except OSError:
                pass
