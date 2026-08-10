"""
tests/properties/test_property_07_provider_opacity.py
Property 7: Provider abstraction opacity
Validates Requirements 3.2.

The Provider Abstraction Layer routes inference requests to a concrete
LLM_Provider without exposing backend-specific parameters to the agent.
This means the agent-visible surface — CompletionRequest, CompletionResponse,
the four LLMProvider methods (complete, structured_output, embed, health_check) —
must remain identical regardless of which backend is configured (llama-cpp,
Ollama, vLLM, OpenAI-compatible, …).

The test asserts four invariants:

  1. Static invariant — CompletionRequest fields are exactly the documented
     opaque set (prompt, max_tokens, temperature, system, stop). No backend
     identifiers (model_path, n_ctx, repeat_penalty, base_url, api_key, …)
     may appear.

  2. Static invariant — CompletionResponse fields are exactly the documented
     opaque set (text, model_id, prompt_tokens, completion_tokens,
     latency_ms). No backend internals (raw_chunks, llama_handle, …) leak.

  3. Static invariant — LLMProvider Protocol exposes exactly four async
     methods (complete, structured_output, embed, health_check). No
     backend-specific callable (eval_logits, set_seed, raw_token_ids, …)
     is part of the contract.

  4. Dynamic invariant — for ANY valid CompletionRequest, two independent
     fake providers ("alpha", "beta") that both implement the protocol
     return CompletionResponse instances with the SAME field set; the
     agent code path must therefore work identically regardless of which
     provider is plugged in (i.e., agent code never branches on backend
     type).
"""

from __future__ import annotations

import inspect
from typing import get_type_hints

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.providers.base import (
    CompletionRequest,
    CompletionResponse,
    LLMProvider,
)


# ---------------------------------------------------------------------------
# Documented opaque schema (the contract)
# ---------------------------------------------------------------------------

#: Exact public field set CompletionRequest may expose.
EXPECTED_REQUEST_FIELDS: frozenset[str] = frozenset(
    {"prompt", "max_tokens", "temperature", "system", "stop"}
)

#: Exact public field set CompletionResponse may expose.
EXPECTED_RESPONSE_FIELDS: frozenset[str] = frozenset(
    {"text", "model_id", "prompt_tokens", "completion_tokens", "latency_ms"}
)

#: Exact set of async methods every provider must expose to agents.
EXPECTED_PROVIDER_METHODS: frozenset[str] = frozenset(
    {"complete", "structured_output", "embed", "health_check"}
)

#: Substrings that, if found in any agent-visible field name or method name,
#: would indicate a backend-specific parameter has leaked through the
#: abstraction. Drawn from common llama.cpp, Ollama, vLLM, and OpenAI client
#: identifiers.
BACKEND_LEAK_TOKENS: tuple[str, ...] = (
    "llama",
    "ollama",
    "vllm",
    "openai",
    "n_ctx",
    "n_gpu",
    "n_threads",
    "model_path",
    "gguf",
    "repeat_penalty",
    "tfs_z",
    "mirostat",
    "base_url",
    "api_key",
    "engine",
    "deployment",
    "tensor_parallel",
    "logits",
    "raw_token",
)


# ---------------------------------------------------------------------------
# Static invariants — schema opacity
# ---------------------------------------------------------------------------


class TestRequestSchemaOpacity:
    """CompletionRequest must expose only the documented opaque fields."""

    def test_request_fields_match_documented_set(self) -> None:
        actual = frozenset(CompletionRequest.model_fields.keys())
        assert actual == EXPECTED_REQUEST_FIELDS, (
            f"CompletionRequest fields drifted from the documented opaque set.\n"
            f"  expected: {sorted(EXPECTED_REQUEST_FIELDS)}\n"
            f"  actual:   {sorted(actual)}\n"
            f"Adding backend-specific fields breaks Property 7 (Requirement 3.2)."
        )

    def test_no_request_field_name_contains_backend_token(self) -> None:
        for field_name in CompletionRequest.model_fields.keys():
            lowered = field_name.lower()
            for token in BACKEND_LEAK_TOKENS:
                assert token not in lowered, (
                    f"CompletionRequest field {field_name!r} contains "
                    f"backend-specific token {token!r}; this leaks the "
                    f"backend through the agent-visible abstraction."
                )


class TestResponseSchemaOpacity:
    """CompletionResponse must expose only the documented opaque fields."""

    def test_response_fields_match_documented_set(self) -> None:
        actual = frozenset(CompletionResponse.model_fields.keys())
        assert actual == EXPECTED_RESPONSE_FIELDS, (
            f"CompletionResponse fields drifted from the documented opaque "
            f"set.\n"
            f"  expected: {sorted(EXPECTED_RESPONSE_FIELDS)}\n"
            f"  actual:   {sorted(actual)}\n"
            f"Adding backend-specific fields breaks Property 7 (Requirement 3.2)."
        )

    def test_no_response_field_name_contains_backend_token(self) -> None:
        for field_name in CompletionResponse.model_fields.keys():
            lowered = field_name.lower()
            for token in BACKEND_LEAK_TOKENS:
                assert token not in lowered, (
                    f"CompletionResponse field {field_name!r} contains "
                    f"backend-specific token {token!r}; this leaks the "
                    f"backend through the agent-visible abstraction."
                )


class TestProtocolOpacity:
    """LLMProvider Protocol must expose only the documented async methods."""

    def test_protocol_exposes_exactly_documented_methods(self) -> None:
        public_callables = {
            name
            for name, member in inspect.getmembers(LLMProvider)
            if not name.startswith("_") and inspect.isfunction(member)
        }
        assert public_callables == EXPECTED_PROVIDER_METHODS, (
            f"LLMProvider protocol surface drifted.\n"
            f"  expected: {sorted(EXPECTED_PROVIDER_METHODS)}\n"
            f"  actual:   {sorted(public_callables)}\n"
            f"Adding backend-specific callables breaks Property 7 "
            f"(Requirement 3.2)."
        )

    def test_no_protocol_method_name_contains_backend_token(self) -> None:
        for method_name in EXPECTED_PROVIDER_METHODS:
            lowered = method_name.lower()
            for token in BACKEND_LEAK_TOKENS:
                assert token not in lowered, (
                    f"LLMProvider method {method_name!r} contains backend-specific token {token!r}."
                )

    def test_protocol_methods_are_all_async(self) -> None:
        for method_name in EXPECTED_PROVIDER_METHODS:
            method = getattr(LLMProvider, method_name)
            assert inspect.iscoroutinefunction(method), (
                f"LLMProvider.{method_name} must be async; "
                f"sync methods would expose backend threading details."
            )


# ---------------------------------------------------------------------------
# Dynamic invariants — agent-equivalence across backends
# ---------------------------------------------------------------------------


class _OpaqueProvider:
    """Minimal LLMProvider that exposes only the agent-visible surface.

    Two independent instances simulate two distinct backends (alpha, beta).
    Property 7 demands that agent code consuming a CompletionResponse from
    either instance sees an identical field schema.
    """

    def __init__(self, backend_label: str) -> None:
        self._label = backend_label

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        return CompletionResponse(
            text=f"{self._label}:{request.prompt}",
            model_id=f"{self._label}-model",
            prompt_tokens=max(1, len(request.prompt.split())),
            completion_tokens=1,
            latency_ms=0.5,
        )

    async def structured_output(self, request: CompletionRequest, schema: dict) -> dict:
        return {"backend": self._label, "schema_keys": list(schema.keys())}

    async def embed(self, text: str) -> list[float]:
        return [float(len(text))]

    async def health_check(self) -> bool:
        return True


_request_strategy = st.builds(
    CompletionRequest,
    prompt=st.text(min_size=1, max_size=64),
    max_tokens=st.integers(min_value=1, max_value=2048),
    temperature=st.floats(min_value=0.0, max_value=2.0, allow_nan=False, allow_infinity=False),
    system=st.one_of(st.none(), st.text(min_size=0, max_size=128)),
    stop=st.one_of(
        st.none(),
        st.lists(st.text(min_size=1, max_size=8), min_size=0, max_size=4),
    ),
)


class TestAgentEquivalenceAcrossBackends:
    """Agents see identical CompletionResponse schemas regardless of backend."""

    @pytest.mark.asyncio
    @given(request=_request_strategy)
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_two_independent_backends_return_identical_field_set(
        self, request: CompletionRequest
    ) -> None:
        alpha = _OpaqueProvider("alpha")
        beta = _OpaqueProvider("beta")

        response_alpha = await alpha.complete(request)
        response_beta = await beta.complete(request)

        # Agents inspect responses by field name; the field SETS must match.
        alpha_fields = frozenset(response_alpha.model_dump().keys())
        beta_fields = frozenset(response_beta.model_dump().keys())

        assert alpha_fields == beta_fields == EXPECTED_RESPONSE_FIELDS, (
            "Two backends produced CompletionResponse instances with "
            "different field sets; agents would have to branch on backend. "
            f"alpha={sorted(alpha_fields)} beta={sorted(beta_fields)}"
        )

    @pytest.mark.asyncio
    @given(request=_request_strategy)
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_two_independent_backends_satisfy_protocol(
        self, request: CompletionRequest
    ) -> None:
        alpha = _OpaqueProvider("alpha")
        beta = _OpaqueProvider("beta")

        # Both backends must satisfy the Protocol identically; any drift
        # between them would force agent code to branch on backend type.
        assert isinstance(alpha, LLMProvider)
        assert isinstance(beta, LLMProvider)

        # Sanity: the request itself must validate the documented opaque
        # field set; hypothesis-generated requests must not have invented
        # backend-leaking attributes via Pydantic extras.
        request_fields = frozenset(request.model_dump().keys())
        assert request_fields == EXPECTED_REQUEST_FIELDS

    @pytest.mark.asyncio
    async def test_response_carries_no_backend_specific_attribute(self) -> None:
        provider = _OpaqueProvider("alpha")
        response = await provider.complete(CompletionRequest(prompt="hello", max_tokens=8))
        # The serialized response keys must be exactly the opaque set.
        keys = set(response.model_dump().keys())
        assert keys == EXPECTED_RESPONSE_FIELDS

    def test_completion_request_type_hints_are_simple_python(self) -> None:
        """Type annotations must use stdlib/Pydantic types only.

        If a field annotation references a backend-specific class
        (e.g., ``llama_cpp.Llama``) the agent would be coupled to the
        backend at type-check time, violating opacity.
        """
        hints = get_type_hints(CompletionRequest)
        for field, hint in hints.items():
            hint_repr = repr(hint).lower()
            for token in BACKEND_LEAK_TOKENS:
                assert token not in hint_repr, (
                    f"CompletionRequest.{field} type hint references "
                    f"backend-specific token {token!r}: {hint_repr}"
                )

    def test_completion_response_type_hints_are_simple_python(self) -> None:
        """Same opacity check applied to CompletionResponse type hints."""
        hints = get_type_hints(CompletionResponse)
        for field, hint in hints.items():
            hint_repr = repr(hint).lower()
            for token in BACKEND_LEAK_TOKENS:
                assert token not in hint_repr, (
                    f"CompletionResponse.{field} type hint references "
                    f"backend-specific token {token!r}: {hint_repr}"
                )
