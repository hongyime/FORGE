"""
tests/providers/test_llama_cpp.py — Unit tests for the llama-cpp-python provider.

Validates Requirements 3.3, 3.4, 3.6:
  - Conformance to the LLMProvider protocol (3.3)
  - 5-second timeout enforcement raising ProviderUnavailableError (3.4)
  - Audit log entries on every call with provider name, model_id,
    prompt/completion token counts, and latency (3.6)

Tests do NOT require an actual GGUF model — the ``llama_cpp.Llama`` class is
patched at the import site so the provider construction is fully isolated.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import types
from typing import Any
from unittest import mock

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.core.errors import ProviderUnavailableError
from forge.providers import (
    CompletionRequest,
    CompletionResponse,
    LLMProvider,
    LlamaCppProvider,
)


# ── Stub backend ──────────────────────────────────────────────────────────────


class _StubLlama:
    """Drop-in replacement for ``llama_cpp.Llama`` used in tests.

    Records construction args and returns canned responses for chat completion
    and embedding calls. Optionally sleeps to simulate slow inference so we
    can exercise the timeout contract without real model loads.
    """

    def __init__(
        self,
        *,
        chat_response: dict[str, Any] | None = None,
        embedding_response: Any = None,
        delay_seconds: float = 0.0,
        raise_on_call: Exception | None = None,
        **kwargs: Any,
    ) -> None:
        self.chat_response = chat_response or {
            "choices": [{"message": {"role": "assistant", "content": "stub answer"}}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3},
        }
        self.embedding_response = (
            embedding_response
            if embedding_response is not None
            else {
                "data": [{"embedding": [0.1, 0.2, 0.3]}],
                "usage": {"prompt_tokens": 4},
            }
        )
        self.delay_seconds = delay_seconds
        self.raise_on_call = raise_on_call
        self.init_kwargs = kwargs
        self.chat_calls: list[dict[str, Any]] = []
        self.embed_calls: list[dict[str, Any]] = []

    def create_chat_completion(self, **kwargs: Any) -> dict[str, Any]:
        self.chat_calls.append(kwargs)
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        if self.raise_on_call is not None:
            raise self.raise_on_call
        return self.chat_response

    def create_embedding(self, **kwargs: Any) -> Any:
        self.embed_calls.append(kwargs)
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        if self.raise_on_call is not None:
            raise self.raise_on_call
        return self.embedding_response


def _patch_llama(stub_factory: Any) -> mock._patch[Any]:
    """Patch ``llama_cpp.Llama`` so ``LlamaCppProvider.__init__`` resolves to ``stub_factory``.

    A synthetic ``llama_cpp`` module is created if it isn't already importable,
    keeping the test suite operational on hosts where the native extension is
    not installed.
    """
    if "llama_cpp" not in sys.modules:
        sys.modules["llama_cpp"] = types.ModuleType("llama_cpp")
    return mock.patch("llama_cpp.Llama", stub_factory, create=True)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def audit_logger() -> AuditLogger:
    """Provide a fresh AuditLogger instance."""
    return AuditLogger()


@pytest.fixture
def stub_llama() -> _StubLlama:
    """Provide a default stub backend instance shared by the test."""
    return _StubLlama()


# ── Protocol conformance ─────────────────────────────────────────────────────


class TestProtocolConformance:
    """Verify LlamaCppProvider satisfies the LLMProvider protocol (Req 3.3)."""

    def test_provider_satisfies_llm_provider_protocol(self, stub_llama: _StubLlama) -> None:
        with _patch_llama(lambda **_: stub_llama):
            provider = LlamaCppProvider(model_path="/fake/model.gguf", timeout=5.0)

        assert isinstance(provider, LLMProvider)

    def test_provider_name_is_llama_cpp(self, stub_llama: _StubLlama) -> None:
        with _patch_llama(lambda **_: stub_llama):
            provider = LlamaCppProvider(model_path="/fake/model.gguf")

        assert provider.name == "llama_cpp"

    def test_model_id_defaults_to_path_stem(self, stub_llama: _StubLlama) -> None:
        with _patch_llama(lambda **_: stub_llama):
            provider = LlamaCppProvider(model_path="/fake/qwen2.5-coder-7b-q4.gguf")

        assert provider.model_id == "qwen2.5-coder-7b-q4"

    def test_model_id_override(self, stub_llama: _StubLlama) -> None:
        with _patch_llama(lambda **_: stub_llama):
            provider = LlamaCppProvider(
                model_path="/fake/model.gguf",
                model_id="custom-model-v1",
            )

        assert provider.model_id == "custom-model-v1"


# ── Construction failure modes ───────────────────────────────────────────────


class TestConstructionFailures:
    """Verify graceful handling of model load failures (Req 3.4)."""

    def test_load_failure_raises_provider_unavailable(self) -> None:
        def _boom(**_: Any) -> None:
            raise RuntimeError("model file missing")

        with _patch_llama(_boom):
            with pytest.raises(ProviderUnavailableError, match="Failed to load"):
                LlamaCppProvider(model_path="/missing/model.gguf")

    def test_invalid_timeout_rejected(self, stub_llama: _StubLlama) -> None:
        with _patch_llama(lambda **_: stub_llama):
            with pytest.raises(ValueError, match="timeout"):
                LlamaCppProvider(model_path="/fake/model.gguf", timeout=0.0)


# ── Completion happy path ────────────────────────────────────────────────────


class TestComplete:
    """Verify text completion behaviour and audit logging (Req 3.6)."""

    @pytest.mark.asyncio
    async def test_complete_returns_populated_response(
        self, stub_llama: _StubLlama, audit_logger: AuditLogger
    ) -> None:
        with _patch_llama(lambda **_: stub_llama):
            provider = LlamaCppProvider(
                model_path="/fake/model.gguf",
                model_id="test-model",
                audit_logger=audit_logger,
            )

        response = await provider.complete(
            CompletionRequest(prompt="hello", max_tokens=8, temperature=0.0)
        )

        assert isinstance(response, CompletionResponse)
        assert response.text == "stub answer"
        assert response.model_id == "test-model"
        assert response.prompt_tokens == 7
        assert response.completion_tokens == 3
        assert response.latency_ms >= 0.0

    @pytest.mark.asyncio
    async def test_complete_records_audit_entry(
        self, stub_llama: _StubLlama, audit_logger: AuditLogger
    ) -> None:
        with _patch_llama(lambda **_: stub_llama):
            provider = LlamaCppProvider(
                model_path="/fake/model.gguf",
                model_id="test-model",
                audit_logger=audit_logger,
            )

        await provider.complete(CompletionRequest(prompt="hello"))

        entries = [e for e in audit_logger.entries if e.event_type == AuditEventType.LLM_INFERENCE]
        assert len(entries) == 1
        entry = entries[0]
        assert entry.success is True
        assert entry.tool_name == "llama_cpp"
        assert entry.duration_ms is not None
        assert entry.duration_ms >= 0.0

        params = entry.input_params
        assert params is not None
        assert params["provider_name"] == "llama_cpp"
        assert params["model_id"] == "test-model"

        # Token accounting is recorded in output_summary as JSON to avoid
        # collision with the AuditLogger's "token" key redaction pattern.
        assert entry.output_summary is not None
        summary = json.loads(entry.output_summary)
        assert summary["provider_name"] == "llama_cpp"
        assert summary["model_id"] == "test-model"
        assert summary["prompt_tokens"] == 7
        assert summary["completion_tokens"] == 3
        assert summary["latency_ms"] >= 0.0

    @pytest.mark.asyncio
    async def test_complete_forwards_system_and_stop(self, stub_llama: _StubLlama) -> None:
        with _patch_llama(lambda **_: stub_llama):
            provider = LlamaCppProvider(model_path="/fake/model.gguf")

        await provider.complete(
            CompletionRequest(
                prompt="hello",
                system="be terse",
                stop=["END"],
                max_tokens=12,
                temperature=0.2,
            )
        )

        assert len(stub_llama.chat_calls) == 1
        call = stub_llama.chat_calls[0]
        assert call["max_tokens"] == 12
        assert call["temperature"] == 0.2
        assert call["stop"] == ["END"]
        roles = [m["role"] for m in call["messages"]]
        assert roles == ["system", "user"]
        # JSON mode should NOT be set for plain completion
        assert "response_format" not in call


# ── Structured output ────────────────────────────────────────────────────────


class TestStructuredOutput:
    """Verify structured (JSON) output and schema forwarding."""

    @pytest.mark.asyncio
    async def test_structured_output_returns_parsed_dict(self, audit_logger: AuditLogger) -> None:
        payload = {"verdict": "approve", "score": 0.91}
        stub = _StubLlama(
            chat_response={
                "choices": [{"message": {"role": "assistant", "content": json.dumps(payload)}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 11},
            }
        )

        with _patch_llama(lambda **_: stub):
            provider = LlamaCppProvider(
                model_path="/fake/model.gguf",
                model_id="json-model",
                audit_logger=audit_logger,
            )

        schema = {"type": "object", "properties": {"verdict": {"type": "string"}}}
        result = await provider.structured_output(
            CompletionRequest(prompt="grade me"), schema=schema
        )

        assert result == payload

        call = stub.chat_calls[0]
        assert call["response_format"]["type"] == "json_object"
        assert call["response_format"]["schema"] == schema

        entries = [e for e in audit_logger.entries if e.event_type == AuditEventType.LLM_INFERENCE]
        assert len(entries) == 1
        assert entries[0].output_summary is not None
        summary = json.loads(entries[0].output_summary)
        assert summary["completion_tokens"] == 11

    @pytest.mark.asyncio
    async def test_structured_output_invalid_json_raises(self, audit_logger: AuditLogger) -> None:
        stub = _StubLlama(
            chat_response={
                "choices": [{"message": {"role": "assistant", "content": "not json"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }
        )

        with _patch_llama(lambda **_: stub):
            provider = LlamaCppProvider(model_path="/fake/model.gguf", audit_logger=audit_logger)

        with pytest.raises(ProviderUnavailableError, match="non-JSON"):
            await provider.structured_output(CompletionRequest(prompt="bad"), schema={})

        # Failure path still emits an audit entry
        entries = [e for e in audit_logger.entries if e.event_type == AuditEventType.LLM_INFERENCE]
        assert len(entries) == 1
        assert entries[0].success is False


# ── Embeddings ───────────────────────────────────────────────────────────────


class TestEmbed:
    """Verify embedding extraction and audit logging."""

    @pytest.mark.asyncio
    async def test_embed_returns_vector(
        self, stub_llama: _StubLlama, audit_logger: AuditLogger
    ) -> None:
        with _patch_llama(lambda **_: stub_llama):
            provider = LlamaCppProvider(
                model_path="/fake/model.gguf",
                model_id="emb-model",
                audit_logger=audit_logger,
            )

        vector = await provider.embed("hello world")

        assert vector == [0.1, 0.2, 0.3]
        assert len(stub_llama.embed_calls) == 1

        entries = [e for e in audit_logger.entries if e.event_type == AuditEventType.LLM_INFERENCE]
        assert len(entries) == 1
        params = entries[0].input_params
        assert params is not None
        assert params["model_id"] == "emb-model"
        assert entries[0].output_summary is not None
        summary = json.loads(entries[0].output_summary)
        assert summary["prompt_tokens"] == 4
        assert summary["completion_tokens"] == 0


# ── Timeout enforcement ──────────────────────────────────────────────────────


class TestTimeoutEnforcement:
    """Verify the configurable timeout raises ProviderUnavailableError (Req 3.4)."""

    @pytest.mark.asyncio
    async def test_complete_times_out(self, audit_logger: AuditLogger) -> None:
        slow_stub = _StubLlama(delay_seconds=0.5)

        with _patch_llama(lambda **_: slow_stub):
            provider = LlamaCppProvider(
                model_path="/fake/model.gguf",
                timeout=0.05,  # 50 ms
                audit_logger=audit_logger,
            )

        with pytest.raises(ProviderUnavailableError, match="timeout"):
            await provider.complete(CompletionRequest(prompt="slow"))

        entries = [e for e in audit_logger.entries if e.event_type == AuditEventType.LLM_INFERENCE]
        assert len(entries) == 1
        assert entries[0].success is False
        assert entries[0].error_detail is not None
        assert "timeout" in entries[0].error_detail.lower()

    @pytest.mark.asyncio
    async def test_embed_times_out(self, audit_logger: AuditLogger) -> None:
        slow_stub = _StubLlama(delay_seconds=0.5)

        with _patch_llama(lambda **_: slow_stub):
            provider = LlamaCppProvider(
                model_path="/fake/model.gguf",
                timeout=0.05,
                audit_logger=audit_logger,
            )

        with pytest.raises(ProviderUnavailableError):
            await provider.embed("slow")

    @pytest.mark.asyncio
    async def test_backend_exception_normalised(self, audit_logger: AuditLogger) -> None:
        stub = _StubLlama(raise_on_call=RuntimeError("backend kaput"))

        with _patch_llama(lambda **_: stub):
            provider = LlamaCppProvider(
                model_path="/fake/model.gguf",
                audit_logger=audit_logger,
            )

        with pytest.raises(ProviderUnavailableError, match="backend kaput"):
            await provider.complete(CompletionRequest(prompt="x"))


# ── Health check ─────────────────────────────────────────────────────────────


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_health_check_true_on_success(self, stub_llama: _StubLlama) -> None:
        with _patch_llama(lambda **_: stub_llama):
            provider = LlamaCppProvider(model_path="/fake/model.gguf")

        assert await provider.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_false_on_failure(self) -> None:
        stub = _StubLlama(raise_on_call=RuntimeError("nope"))

        with _patch_llama(lambda **_: stub):
            provider = LlamaCppProvider(model_path="/fake/model.gguf")

        assert await provider.health_check() is False
