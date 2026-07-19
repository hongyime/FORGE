"""
forge/providers/llama_cpp.py — llama-cpp-python LLMProvider backend.

Loads a GGUF model from FORGE_LLM_MODEL_PATH and serves text completion,
schema-constrained structured output, and embedding requests through the
backend-agnostic LLMProvider protocol defined in forge.providers.base.

Timeout contract (Requirement 3.4):
    Every public call enforces a configurable timeout (sourced from
    FORGE_PROVIDER_TIMEOUT, default 5 seconds) via ``asyncio.wait_for``.
    Blocking llama_cpp calls are dispatched to a worker thread with
    ``asyncio.to_thread``. Backend errors and timeouts are surfaced as
    ``ProviderUnavailableError`` so agents never block indefinitely.

Audit contract (Requirement 3.6):
    On every successful or failed call, the provider records an audit entry
    of type ``AuditEventType.LLM_INFERENCE`` capturing provider name,
    model_id, prompt_tokens, completion_tokens, and latency_ms. The entry
    is logged through the supplied :class:`forge.audit.logger.AuditLogger`.

Lazy import (Requirement 3.3):
    ``llama_cpp`` is imported inside ``__init__`` rather than at module
    load so this module can be imported in test environments and on hosts
    without the C extension installed. The Llama instance is constructed
    eagerly during ``__init__`` so subsequent calls do not pay model-load
    cost on the hot path.

Requirements: 3.3, 3.4, 3.6
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any, cast

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType
from forge.core.errors import ProviderUnavailableError
from forge.providers.base import CompletionRequest, CompletionResponse

__all__ = ["LlamaCppProvider"]

_LOG = logging.getLogger(__name__)

_PROVIDER_NAME = "llama_cpp"
_DEFAULT_TIMEOUT_SECONDS = 5.0


class LlamaCppProvider:
    """LLMProvider backend powered by llama-cpp-python.

    The provider loads a GGUF model from disk during construction and exposes
    text completion, structured output, and embedding methods through the
    LLMProvider protocol. Each call enforces a per-request timeout and emits
    an audit entry capturing latency and token accounting.

    Args:
        model_path: Filesystem path to the GGUF model. Typically sourced from
            FORGE_LLM_MODEL_PATH at the call site.
        model_id: Optional human-readable model identifier. Defaults to the
            model file's stem (e.g. ``"qwen2.5-coder-7b-instruct-q4_k_m"``).
        timeout: Per-request timeout in seconds (FORGE_PROVIDER_TIMEOUT).
            Defaults to 5.0 to honour the design contract.
        audit_logger: Optional audit sink. When provided, every call records
            an LLM_INFERENCE entry; when ``None``, no audit entry is written.

    Raises:
        ProviderUnavailableError: If ``llama_cpp`` is not installed or the
            model cannot be loaded from ``model_path``.
    """

    def __init__(
        self,
        model_path: str,
        model_id: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be a positive number of seconds")

        self._model_path = model_path
        self._model_id = model_id or Path(model_path).stem or _PROVIDER_NAME
        self._timeout = float(timeout)
        self._audit_logger = audit_logger

        # Lazy import keeps module importable in test environments without
        # the native llama_cpp extension. If the import or constructor fails
        # we surface the failure as ProviderUnavailableError so callers can
        # treat it uniformly with runtime backend failures.
        try:
            from llama_cpp import Llama
        except ImportError as exc:  # pragma: no cover - exercised when extension absent
            raise ProviderUnavailableError(
                f"llama-cpp-python is not installed: {exc}"
            ) from exc

        try:
            self._llm: Any = Llama(model_path=str(model_path), verbose=False)
        except Exception as exc:  # noqa: BLE001 - surface any backend init failure
            raise ProviderUnavailableError(
                f"Failed to load GGUF model from {model_path!r}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Protocol metadata
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        """Stable provider identifier used by the registry and audit log."""
        return _PROVIDER_NAME

    @property
    def model_id(self) -> str:
        """Human-readable identifier of the loaded GGUF model."""
        return self._model_id

    # ------------------------------------------------------------------
    # LLMProvider methods
    # ------------------------------------------------------------------

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Generate a text completion for the given request."""
        correlation_id = uuid.uuid4().hex
        start = time.perf_counter()

        try:
            raw = await self._call_with_timeout(
                self._invoke_completion, request, json_mode=False
            )
        except ProviderUnavailableError as exc:
            await self._log_failure(correlation_id, start, str(exc))
            raise

        latency_ms = (time.perf_counter() - start) * 1000.0
        text, prompt_tokens, completion_tokens = self._unpack_completion(raw)
        response = CompletionResponse(
            text=text,
            model_id=self._model_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
        )
        await self._log_success(
            correlation_id=correlation_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
        )
        return response

    async def structured_output(
        self, request: CompletionRequest, schema: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate a JSON-mode response constrained by ``schema``."""
        correlation_id = uuid.uuid4().hex
        start = time.perf_counter()

        try:
            raw = await self._call_with_timeout(
                self._invoke_completion,
                request,
                json_mode=True,
                schema=schema,
            )
        except ProviderUnavailableError as exc:
            await self._log_failure(correlation_id, start, str(exc))
            raise

        latency_ms = (time.perf_counter() - start) * 1000.0
        text, prompt_tokens, completion_tokens = self._unpack_completion(raw)

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            message = f"llama_cpp produced non-JSON structured output: {exc}"
            await self._log_failure(correlation_id, start, message)
            raise ProviderUnavailableError(message) from exc

        if not isinstance(parsed, dict):
            message = (
                "llama_cpp structured output must be a JSON object; "
                f"got {type(parsed).__name__}"
            )
            await self._log_failure(correlation_id, start, message)
            raise ProviderUnavailableError(message)

        await self._log_success(
            correlation_id=correlation_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
        )
        return cast(dict[str, Any], parsed)

    async def embed(self, text: str) -> list[float]:
        """Return a vector embedding for ``text``."""
        correlation_id = uuid.uuid4().hex
        start = time.perf_counter()

        try:
            raw = await self._call_with_timeout(self._invoke_embed, text)
        except ProviderUnavailableError as exc:
            await self._log_failure(correlation_id, start, str(exc))
            raise

        latency_ms = (time.perf_counter() - start) * 1000.0
        vector, prompt_tokens = self._unpack_embedding(raw)

        await self._log_success(
            correlation_id=correlation_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=0,
            latency_ms=latency_ms,
        )
        return vector

    async def health_check(self) -> bool:
        """Return True if the loaded model can respond to a trivial prompt."""
        try:
            await self.complete(
                CompletionRequest(prompt="ping", max_tokens=1, temperature=0.0)
            )
        except ProviderUnavailableError:
            return False
        return True

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _call_with_timeout(
        self,
        func: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Run a blocking llama_cpp call in a worker thread under a timeout."""
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(func, *args, **kwargs),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ProviderUnavailableError(
                f"llama_cpp call exceeded {self._timeout:.1f}s timeout"
            ) from exc
        except ProviderUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalise backend failures
            raise ProviderUnavailableError(
                f"llama_cpp backend failure: {exc}"
            ) from exc

    def _invoke_completion(
        self,
        request: CompletionRequest,
        *,
        json_mode: bool,
        schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Blocking llama_cpp completion call. Runs inside a worker thread."""
        messages: list[dict[str, str]] = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})

        kwargs: dict[str, Any] = {
            "messages": messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        if request.stop:
            kwargs["stop"] = list(request.stop)
        if json_mode:
            response_format: dict[str, Any] = {"type": "json_object"}
            if schema is not None:
                response_format["schema"] = schema
            kwargs["response_format"] = response_format

        result = self._llm.create_chat_completion(**kwargs)
        return cast(dict[str, Any], result)

    def _invoke_embed(self, text: str) -> Any:
        """Blocking llama_cpp embedding call. Runs inside a worker thread."""
        return self._llm.create_embedding(input=text)

    @staticmethod
    def _unpack_completion(raw: dict[str, Any]) -> tuple[str, int, int]:
        """Extract text, prompt_tokens, completion_tokens from a chat result."""
        choices = raw.get("choices") or []
        text = ""
        if choices:
            message = choices[0].get("message") or {}
            text = str(message.get("content") or "")
        usage = raw.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens", 0))
        completion_tokens = int(usage.get("completion_tokens", 0))
        return text, prompt_tokens, completion_tokens

    @staticmethod
    def _unpack_embedding(raw: Any) -> tuple[list[float], int]:
        """Extract the embedding vector and prompt token count."""
        # llama_cpp.create_embedding returns either a dict with ``data`` →
        # ``embedding`` or a bare list[float], depending on version.
        if isinstance(raw, dict):
            data = raw.get("data") or []
            vector_raw: Any = []
            if data:
                vector_raw = data[0].get("embedding") or []
            usage = raw.get("usage") or {}
            prompt_tokens = int(usage.get("prompt_tokens", 0))
        else:
            vector_raw = raw
            prompt_tokens = 0

        vector = [float(x) for x in vector_raw]
        return vector, prompt_tokens

    async def _log_success(
        self,
        *,
        correlation_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float,
    ) -> None:
        """Append an LLM_INFERENCE audit entry for a successful call.

        Token counts are encoded as a JSON object in ``output_summary`` rather
        than placed in ``input_params``. The AuditLogger redacts any
        ``input_params`` key matching the regex ``token`` (intended for
        access-token redaction); routing accounting metrics through
        ``output_summary`` preserves the values while keeping the redaction
        contract intact for genuine secrets.
        """
        if self._audit_logger is None:
            return
        summary = json.dumps(
            {
                "provider_name": _PROVIDER_NAME,
                "model_id": self._model_id,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "latency_ms": latency_ms,
            },
            sort_keys=True,
        )
        entry = AuditEntry(
            correlation_id=correlation_id,
            event_type=AuditEventType.LLM_INFERENCE,
            tool_name=_PROVIDER_NAME,
            input_params={
                "provider_name": _PROVIDER_NAME,
                "model_id": self._model_id,
            },
            output_summary=summary,
            duration_ms=latency_ms,
            success=True,
        )
        await self._audit_logger.log(entry)

    async def _log_failure(
        self, correlation_id: str, start: float, error_detail: str
    ) -> None:
        """Append an LLM_INFERENCE audit entry for a failed call."""
        if self._audit_logger is None:
            return
        latency_ms = (time.perf_counter() - start) * 1000.0
        summary = json.dumps(
            {
                "provider_name": _PROVIDER_NAME,
                "model_id": self._model_id,
                "latency_ms": latency_ms,
            },
            sort_keys=True,
        )
        entry = AuditEntry(
            correlation_id=correlation_id,
            event_type=AuditEventType.LLM_INFERENCE,
            tool_name=_PROVIDER_NAME,
            input_params={
                "provider_name": _PROVIDER_NAME,
                "model_id": self._model_id,
            },
            output_summary=summary,
            duration_ms=latency_ms,
            success=False,
            error_detail=error_detail,
        )
        await self._audit_logger.log(entry)


# Module-level note: ``LlamaCppProvider`` satisfies the LLMProvider Protocol
# defined in ``forge.providers.base``. Tests verify conformance with
# ``isinstance(provider, LLMProvider)`` (the Protocol is ``runtime_checkable``).
