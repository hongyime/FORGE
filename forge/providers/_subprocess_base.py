"""
forge/providers/_subprocess_base.py - Shared base for CLI shell-out providers.

Three providers (``claude_code``, ``codex_cli``, ``gemini_cli``) share the
same shape: spawn a CLI binary with a prompt argument, capture stdout as
the completion text, and surface non-zero exit codes as
``ProviderUnavailableError``. This base class factors out the timeout,
process termination, and error-handling boilerplate so each concrete
subclass becomes ~30 LOC.

Subclasses override class-level metadata to plug in:
    * ``binary_name`` - executable to look up on PATH
    * ``completion_args`` - argv tail that takes the prompt as its last
      element (e.g. ``["--print"]`` for claude, ``["exec"]`` for codex)
    * ``version_args`` - argv that prints the version and returns 0 when
      the binary is healthy (e.g. ``["--version"]``)
    * ``backend_name`` / ``default_model_id`` for audit / discovery
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time

from forge.core.errors import ProviderUnavailableError
from forge.providers.base import (
    CompletionRequest,
    CompletionResponse,
)

__all__ = ["SubprocessProvider"]

_LOG = logging.getLogger(__name__)


class SubprocessProvider:
    """Base class for CLI shell-out providers.

    Args:
        binary: Path or name of the executable. Resolved via
            :func:`shutil.which` if not absolute.
        timeout: Per-call wall-clock cap in seconds.
        model_id: Logical model identifier reported in audit / responses.
    """

    # -- Subclasses override these class attrs --------------------------
    backend_name: str = "subprocess"
    default_model_id: str = "subprocess-cli"
    completion_args: tuple[str, ...] = ()  # argv prefix; prompt appended last
    version_args: tuple[str, ...] = ("--version",)

    def __init__(
        self,
        *,
        binary: str | None = None,
        timeout: float = 120.0,
        model_id: str | None = None,
    ) -> None:
        binary_name = binary or self.backend_name
        resolved = shutil.which(binary_name) or shutil.which(f"{binary_name}.cmd")
        if not resolved:
            raise ProviderUnavailableError(
                f"{self.backend_name}: binary not found on PATH "
                f"(looked for {binary_name!r})"
            )
        self._binary = resolved
        self._timeout = float(timeout)
        self._model_id = model_id or self.default_model_id

    # ------------------------------------------------------------------
    # Public read-only metadata
    # ------------------------------------------------------------------

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def binary_path(self) -> str:
        return self._binary

    # ------------------------------------------------------------------
    # Subclass hooks
    # ------------------------------------------------------------------

    def _format_prompt(self, request: CompletionRequest) -> str:
        """Combine ``request.system`` and ``request.prompt`` into one string
        for the CLI binary.

        Default: ``[SYSTEM]...[/SYSTEM]`` tag wrapping. Works for
        ``claude --print``, which treats the entire argument as a single
        user message. Subclasses override for CLIs that misinterpret the
        tag syntax (e.g. ``codex exec`` reads ``[SYSTEM]`` as a literal
        instruction).
        """
        if not request.system:
            return request.prompt
        return f"[SYSTEM]\n{request.system}\n[/SYSTEM]\n\n{request.prompt}"

    def _extra_env(self) -> dict[str, str | None]:
        """Environment variable overrides for the subprocess.

        Return ``{"KEY": "value"}`` to set, ``{"KEY": None}`` to unset.
        Merged on top of the parent process environment before spawn.
        Default: empty. Subclasses override for CLIs that misbehave under
        the default operator env (e.g. ``gemini`` demands
        ``TERM=xterm-256color``).
        """
        return {}

    # ------------------------------------------------------------------
    # LLMProvider protocol
    # ------------------------------------------------------------------

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        prompt = self._format_prompt(request)
        argv = [self._binary, *self.completion_args, prompt]

        # Compose environment: start from parent, apply subclass overrides.
        import os as _os  # noqa: PLC0415
        env = _os.environ.copy()
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

        if proc.returncode != 0:
            stderr = stderr_bytes.decode("utf-8", errors="replace")[:500]
            stdout = stdout_bytes.decode("utf-8", errors="replace")[:500]
            # CLI wrappers (claude, codex, gemini) often send user-facing error
            # messages like rate-limit notices to stdout, not stderr. Include
            # both so the surfaced error is actually useful.
            detail = stderr or stdout or "<no output>"
            raise ProviderUnavailableError(
                f"{self.backend_name}: exit={proc.returncode} detail={detail!r}"
            )

        text = stdout_bytes.decode("utf-8", errors="replace").strip()
        latency_ms = (time.perf_counter() - t0) * 1000.0
        # CLI shell-outs don't report token counts; rough estimate so
        # downstream cost / budget logic has a non-zero starting point.
        return CompletionResponse(
            text=text,
            model_id=self._model_id,
            prompt_tokens=max(1, len(prompt) // 4),
            completion_tokens=max(1, len(text) // 4),
            latency_ms=max(0.0, latency_ms),
        )

    async def structured_output(
        self,
        request: CompletionRequest,
        schema: dict[str, object],
    ) -> dict[str, object]:
        instructed = CompletionRequest(
            prompt=(
                f"{request.prompt}\n\n"
                "Respond with ONLY a single JSON object conforming to this "
                f"schema. No preamble, no explanation:\n{json.dumps(schema)}"
            ),
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            system=request.system,
            stop=request.stop,
        )
        resp = await self.complete(instructed)
        text = resp.text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        try:
            return dict(json.loads(text))
        except (json.JSONDecodeError, TypeError) as exc:
            raise ProviderUnavailableError(
                f"{self.backend_name}: structured_output non-JSON: {text[:200]!r}"
            ) from exc

    async def embed(self, text: str) -> list[float]:
        raise ProviderUnavailableError(
            f"{self.backend_name}: embeddings not supported via the CLI"
        )

    async def health_check(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self._binary, *self.version_args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5.0)
            return proc.returncode == 0
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            return False
