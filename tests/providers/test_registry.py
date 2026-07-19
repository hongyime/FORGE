"""
tests/providers/test_registry.py — Unit tests for forge.providers.registry.

Covers:
  * Registering a valid stub provider succeeds and is retrievable via get().
  * Registering a non-conforming object is rejected with a logged reason.
  * get_active() reads from PlatformSettings.llm_provider.
  * get() raises KeyError for unknown names.
  * register() rejects duplicate names by default; replace=True overwrites.
  * Built-in stub backends (ollama, vllm, openai_compatible) raise
    NotImplementedError until proper factories are registered.

Validates Requirements: 3.5
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.providers.base import (
    CompletionRequest,
    CompletionResponse,
    LLMProvider,
)
from forge.providers.registry import ProviderRegistry


# ── Stub providers ────────────────────────────────────────────────────────────


class _StubProvider:
    """Minimal LLMProvider implementation for tests."""

    def __init__(self, model_id: str = "stub-model") -> None:
        self._model_id = model_id

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        return CompletionResponse(
            text=f"echo:{request.prompt}",
            model_id=self._model_id,
            prompt_tokens=len(request.prompt.split()),
            completion_tokens=1,
            latency_ms=0.1,
        )

    async def structured_output(
        self, request: CompletionRequest, schema: dict
    ) -> dict:
        return {"prompt": request.prompt, "schema_keys": list(schema.keys())}

    async def embed(self, text: str) -> list[float]:
        return [float(len(text))]

    async def health_check(self) -> bool:
        return True


class _PartialProvider:
    """Object that does NOT satisfy the LLMProvider protocol (missing embed)."""

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        raise NotImplementedError

    async def structured_output(
        self, request: CompletionRequest, schema: dict
    ) -> dict:
        raise NotImplementedError

    async def health_check(self) -> bool:
        return False


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestProviderRegistration:
    """Registering valid and invalid providers."""

    def test_register_valid_stub_provider_succeeds(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        registry.register("stub", lambda: _StubProvider())

        provider = registry.get("stub")

        assert isinstance(provider, LLMProvider)
        assert "stub" in registry
        assert "stub" in registry.list_providers()

    def test_register_duplicate_name_raises_value_error(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        registry.register("stub", lambda: _StubProvider())

        with pytest.raises(ValueError, match="already registered"):
            registry.register("stub", lambda: _StubProvider())

    def test_register_duplicate_with_replace_true_overwrites(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        registry.register("stub", lambda: _StubProvider("first"))

        # Resolve once so the cache is populated, then register a replacement.
        first = registry.get("stub")
        registry.register("stub", lambda: _StubProvider("second"), replace=True)
        second = registry.get("stub")

        assert first is not second

    def test_register_rejects_non_callable_factory(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        with pytest.raises(TypeError, match="must be callable"):
            registry.register("bad", "not-a-factory")  # type: ignore[arg-type]

    def test_register_rejects_empty_name(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        with pytest.raises(ValueError, match="non-empty string"):
            registry.register("", lambda: _StubProvider())

    @pytest.mark.asyncio
    async def test_register_emits_audit_event(self) -> None:
        audit = AuditLogger()
        registry = ProviderRegistry(audit=audit, seed_builtins=False)
        registry.register("stub", lambda: _StubProvider())

        # The registration event is emitted via asyncio.create_task when a
        # loop is running; await one tick so it lands in the log.
        import asyncio

        await asyncio.sleep(0)

        events = [e for e in audit.entries if "provider_registered" in (e.output_summary or "")]
        assert events, "Expected a provider_registered audit event"
        assert events[0].event_type == AuditEventType.STATE_TRANSITION


class TestProviderResolution:
    """Resolving providers via get() and get_active()."""

    def test_get_unknown_name_raises_key_error(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        with pytest.raises(KeyError, match="No provider registered"):
            registry.get("does_not_exist")

    def test_get_caches_instance(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        call_count = {"n": 0}

        def factory() -> LLMProvider:
            call_count["n"] += 1
            return _StubProvider()

        registry.register("stub", factory)
        first = registry.get("stub")
        second = registry.get("stub")

        assert first is second
        assert call_count["n"] == 1

    def test_get_rejects_non_conforming_candidate(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        registry.register("partial", lambda: _PartialProvider())  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="LLMProvider protocol"):
            registry.get("partial")

    @pytest.mark.asyncio
    async def test_get_logs_rejection_to_audit(self) -> None:
        audit = AuditLogger()
        registry = ProviderRegistry(audit=audit, seed_builtins=False)
        registry.register("partial", lambda: _PartialProvider())  # type: ignore[arg-type]

        with pytest.raises(TypeError):
            registry.get("partial")

        import asyncio

        await asyncio.sleep(0)

        rejected = [
            e
            for e in audit.entries
            if (e.output_summary or "").startswith("provider_rejected:")
        ]
        assert rejected, "Rejection should be recorded in the audit log"
        assert rejected[0].success is False
        assert rejected[0].error_detail is not None
        assert "LLMProvider protocol" in rejected[0].error_detail


class TestGetActive:
    """get_active() reads from PlatformSettings."""

    def test_get_active_reads_llm_provider_setting(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        registry.register("custom_active", lambda: _StubProvider("active"))

        # Clear unrelated FORGE_* env vars to avoid bleed-through.
        env = {k: v for k, v in os.environ.items() if not k.startswith("FORGE_")}
        env["FORGE_LLM_PROVIDER"] = "custom_active"
        with patch.dict(os.environ, env, clear=True):
            provider = registry.get_active()

        assert isinstance(provider, LLMProvider)

    def test_get_active_raises_for_unknown_setting(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        env = {k: v for k, v in os.environ.items() if not k.startswith("FORGE_")}
        env["FORGE_LLM_PROVIDER"] = "ghost_backend"
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(KeyError):
                registry.get_active()


class TestBuiltinFactories:
    """Built-in factories are seeded lazily and stub backends raise."""

    def test_seeded_builtin_names_present(self) -> None:
        registry = ProviderRegistry()
        names = registry.list_providers()
        assert {"llama_cpp", "ollama", "vllm", "openai_compatible"}.issubset(set(names))

    @pytest.mark.parametrize("name", ["ollama", "vllm", "openai_compatible"])
    def test_stub_backends_raise_not_implemented(self, name: str) -> None:
        registry = ProviderRegistry()
        with pytest.raises(NotImplementedError):
            registry.get(name)

    def test_non_mvp_backend_factories_remain_lazy(self) -> None:
        """Stub factories for ollama / vllm / openai_compatible must not
        import their backend libraries at registry construction time.

        Only invoking ``get('ollama' | 'vllm' | 'openai_compatible')`` may
        attempt the backend import. Constructing the registry alone must
        be import-cost-free for non-MVP backends so test environments and
        hosts that ship only the MVP backend can use the registry.
        """
        import subprocess
        import sys
        import textwrap

        script = textwrap.dedent(
            """
            import sys
            from forge.providers.registry import ProviderRegistry

            registry = ProviderRegistry()

            forbidden = {
                "ollama",
                "vllm",
                "openai",  # openai-compatible client family
            }
            leaked = sorted(m for m in sys.modules if m.split(".")[0] in forbidden)
            assert not leaked, (
                f"Non-MVP backend libraries imported eagerly: {leaked}"
            )
            # Also assert the names ARE registered, just not invoked.
            for name in ("ollama", "vllm", "openai_compatible"):
                assert name in registry, (
                    f"Stub factory for {name!r} was not registered"
                )
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Subprocess failed:\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
