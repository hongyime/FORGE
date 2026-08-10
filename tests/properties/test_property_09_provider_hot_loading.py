"""
tests/properties/test_property_09_provider_hot_loading.py
Property 9: Provider hot-loading
Validates Requirements 3.5.

The Provider Abstraction Layer must support loading additional LLM provider
backends (Ollama, vLLM, OpenAI-compatible, custom) at startup without
requiring changes to agent code.  Each candidate factory is validated
against the runtime-checkable :class:`LLMProvider` protocol; conformant
candidates are accepted and resolvable by name, non-conformant candidates
are rejected with :class:`TypeError` and recorded to the audit log.

The test asserts five invariants:

  1. Static invariant — all four built-in factory names (``llama_cpp``,
     ``ollama``, ``vllm``, ``openai_compatible``) are seeded by default.

  2. Dynamic invariant — for any well-formed registration name, registering
     a conformant factory makes the provider resolvable via
     :meth:`ProviderRegistry.get`, and the resolved instance satisfies
     :class:`LLMProvider`.

  3. Dynamic invariant — for any well-formed registration name, registering
     a non-conformant factory (object missing one or more required methods)
     causes :meth:`ProviderRegistry.get` to raise :class:`TypeError` whose
     message identifies the missing protocol surface.

  4. Dynamic invariant — duplicate registrations under the same name are
     rejected unless ``replace=True`` is passed; with ``replace=True`` the
     cached instance is invalidated so subsequent calls exercise the new
     factory.

  5. Dynamic invariant — registration is idempotent w.r.t. unrelated names:
     adding ``"alpha"`` does not affect resolution of any other name.
"""

from __future__ import annotations

import string
from typing import Any

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from forge.providers.base import (
    CompletionRequest,
    CompletionResponse,
    LLMProvider,
)
from forge.providers.registry import ProviderRegistry


# ---------------------------------------------------------------------------
# Stub providers
# ---------------------------------------------------------------------------


class _ConformantProvider:
    """Minimal LLMProvider implementation that satisfies the full protocol."""

    def __init__(self, model_id: str = "stub-model") -> None:
        self._model_id = model_id

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        return CompletionResponse(
            text=f"echo:{request.prompt}",
            model_id=self._model_id,
            prompt_tokens=max(1, len(request.prompt.split())),
            completion_tokens=1,
            latency_ms=0.1,
        )

    async def structured_output(self, request: CompletionRequest, schema: dict) -> dict:
        return {"prompt": request.prompt, "schema_keys": list(schema.keys())}

    async def embed(self, text: str) -> list[float]:
        return [float(len(text))]

    async def health_check(self) -> bool:
        return True


class _MissingEmbed:
    """Non-conformant: lacks ``embed``."""

    async def complete(self, request: CompletionRequest) -> CompletionResponse:  # pragma: no cover
        raise NotImplementedError

    async def structured_output(
        self, request: CompletionRequest, schema: dict
    ) -> dict:  # pragma: no cover
        raise NotImplementedError

    async def health_check(self) -> bool:  # pragma: no cover
        return False


class _MissingHealthCheck:
    """Non-conformant: lacks ``health_check``."""

    async def complete(self, request: CompletionRequest) -> CompletionResponse:  # pragma: no cover
        raise NotImplementedError

    async def structured_output(
        self, request: CompletionRequest, schema: dict
    ) -> dict:  # pragma: no cover
        raise NotImplementedError

    async def embed(self, text: str) -> list[float]:  # pragma: no cover
        return []


class _MissingComplete:
    """Non-conformant: lacks ``complete``."""

    async def structured_output(
        self, request: CompletionRequest, schema: dict
    ) -> dict:  # pragma: no cover
        raise NotImplementedError

    async def embed(self, text: str) -> list[float]:  # pragma: no cover
        return []

    async def health_check(self) -> bool:  # pragma: no cover
        return False


class _MissingStructuredOutput:
    """Non-conformant: lacks ``structured_output``."""

    async def complete(self, request: CompletionRequest) -> CompletionResponse:  # pragma: no cover
        raise NotImplementedError

    async def embed(self, text: str) -> list[float]:  # pragma: no cover
        return []

    async def health_check(self) -> bool:  # pragma: no cover
        return False


_NON_CONFORMANT_CLASSES = (
    _MissingEmbed,
    _MissingHealthCheck,
    _MissingComplete,
    _MissingStructuredOutput,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


_BUILTIN_NAMES = frozenset({"llama_cpp", "ollama", "vllm", "openai_compatible"})

#: Provider name characters: lowercase + digit + underscore so the name is
#: a valid environment-variable suffix.
_NAME_CHAR = st.sampled_from(string.ascii_lowercase + string.digits + "_")
_provider_name_strategy = st.text(alphabet=_NAME_CHAR, min_size=3, max_size=24).filter(
    # Avoid colliding with built-in names; this property is about
    # *additional* hot-loaded providers, not overrides of built-ins.
    lambda s: s not in _BUILTIN_NAMES and not s.startswith("_")
)


# ---------------------------------------------------------------------------
# Static invariants
# ---------------------------------------------------------------------------


class TestBuiltinSeeding:
    """All four built-in backend names are pre-registered."""

    def test_default_registry_seeds_four_builtins(self) -> None:
        registry = ProviderRegistry()
        names = set(registry.list_providers())
        assert _BUILTIN_NAMES.issubset(names), (
            f"Built-in seed missing names: {sorted(_BUILTIN_NAMES - names)}"
        )

    def test_seed_builtins_false_yields_empty_registry(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        assert registry.list_providers() == []


# ---------------------------------------------------------------------------
# Dynamic invariants — conformant registrations
# ---------------------------------------------------------------------------


class TestConformantRegistration:
    """Registering a conformant factory makes it resolvable."""

    @given(name=_provider_name_strategy)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_conformant_factory_is_resolvable(self, name: str) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        registry.register(name, lambda: _ConformantProvider())

        provider = registry.get(name)

        assert isinstance(provider, LLMProvider)
        assert name in registry
        assert name in registry.list_providers()

    @given(names=st.lists(_provider_name_strategy, min_size=2, max_size=6, unique=True))
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_unrelated_registrations_do_not_interfere(self, names: list[str]) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        for n in names:
            registry.register(n, lambda label=n: _ConformantProvider(label))

        # Each name resolves independently and yields a distinct cached
        # instance whose model_id reflects the registration label.
        seen_ids: set[int] = set()
        for n in names:
            instance = registry.get(n)
            assert isinstance(instance, LLMProvider)
            seen_ids.add(id(instance))
        assert len(seen_ids) == len(names), (
            "Each conformant registration must yield a distinct instance."
        )


# ---------------------------------------------------------------------------
# Dynamic invariants — non-conformant rejections
# ---------------------------------------------------------------------------


class TestNonConformantRejection:
    """Non-conformant factories raise TypeError on resolve."""

    @given(
        name=_provider_name_strategy,
        broken_cls=st.sampled_from(_NON_CONFORMANT_CLASSES),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_factory_returning_non_conformant_object_is_rejected(
        self, name: str, broken_cls: type
    ) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        registry.register(name, lambda cls=broken_cls: cls())  # type: ignore[arg-type]

        with pytest.raises(TypeError) as exc_info:
            registry.get(name)

        message = str(exc_info.value)
        assert "LLMProvider protocol" in message, (
            f"Rejection message must reference the LLMProvider protocol contract; got: {message!r}"
        )
        # The message must identify which protocol surface is missing so
        # operators can fix the implementation rather than guess.
        for required_method in ("complete", "structured_output", "embed", "health_check"):
            assert required_method in message, (
                f"Rejection message missing reference to required "
                f"protocol method {required_method!r}: {message!r}"
            )


# ---------------------------------------------------------------------------
# Dynamic invariants — duplicate handling
# ---------------------------------------------------------------------------


class TestDuplicateHandling:
    """Duplicate names rejected unless replace=True; cache invalidates on replace."""

    @given(name=_provider_name_strategy)
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_duplicate_without_replace_raises_value_error(self, name: str) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        registry.register(name, lambda: _ConformantProvider())

        with pytest.raises(ValueError, match="already registered"):
            registry.register(name, lambda: _ConformantProvider())

    @given(name=_provider_name_strategy)
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_replace_invalidates_cached_instance(self, name: str) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        registry.register(name, lambda: _ConformantProvider("first"))
        first = registry.get(name)

        registry.register(name, lambda: _ConformantProvider("second"), replace=True)
        second = registry.get(name)

        # The cache is invalidated so the second factory is exercised.
        assert first is not second


# ---------------------------------------------------------------------------
# Dynamic invariants — get_active() reads PlatformSettings
# ---------------------------------------------------------------------------


class TestGetActiveHotLoaded:
    """get_active() resolves a hot-loaded backend without code changes."""

    @given(name=_provider_name_strategy)
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_hot_loaded_backend_is_reachable_via_get_active(
        self, name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = ProviderRegistry(seed_builtins=False)
        registry.register(name, lambda: _ConformantProvider(name))

        # Clear unrelated FORGE_* env vars; pin the active backend name.
        for k in list(__import__("os").environ):
            if k.startswith("FORGE_"):
                monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("FORGE_LLM_PROVIDER", name)

        provider = registry.get_active()
        assert isinstance(provider, LLMProvider)


# ---------------------------------------------------------------------------
# Concrete sequence — proof against a hand-crafted scenario
# ---------------------------------------------------------------------------


class TestConcreteHotLoadingScenario:
    """Hand-crafted scenario covering the full hot-load lifecycle."""

    def test_register_resolve_replace_unknown_sequence(self) -> None:
        registry = ProviderRegistry(seed_builtins=False)

        # Step 1: register conformant factory under "alpha".
        registry.register("alpha", lambda: _ConformantProvider("alpha-v1"))
        assert "alpha" in registry

        # Step 2: resolve and confirm protocol conformance + caching.
        a1 = registry.get("alpha")
        a2 = registry.get("alpha")
        assert isinstance(a1, LLMProvider)
        assert a1 is a2

        # Step 3: register a non-conformant "beta" and confirm rejection.
        registry.register("beta", lambda: _MissingEmbed())  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="LLMProvider protocol"):
            registry.get("beta")

        # Step 4: replace "alpha" with replace=True and confirm cache flushed.
        registry.register("alpha", lambda: _ConformantProvider("alpha-v2"), replace=True)
        a3 = registry.get("alpha")
        assert a3 is not a1

        # Step 5: unknown name raises KeyError without affecting the registry.
        with pytest.raises(KeyError, match="No provider registered"):
            registry.get("ghost")
        assert "alpha" in registry  # state intact
