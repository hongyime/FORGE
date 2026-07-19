"""
forge/providers/base.py — LLMProvider protocol and request/response models.

Defines the backend-agnostic interface for LLM inference. Concrete providers
(llama-cpp-python, Ollama, vLLM, OpenAI-compatible) conform to this protocol so
agent code never touches backend-specific parameters. The Provider Abstraction
Layer routes inference requests through this protocol, recording provider name,
model identifier, token count, and latency to the audit log on each call.

Timeout contract:
    The 5-second provider timeout is enforced at call sites (typically the
    Provider Abstraction Layer wrapper or the agent invoking the provider),
    sourced from the FORGE_PROVIDER_TIMEOUT environment variable. When a
    provider fails to respond within the configured window, callers raise
    ``ProviderUnavailableError`` rather than blocking indefinitely. Provider
    implementations themselves should surface backend errors as
    ``ProviderUnavailableError`` whenever they cannot fulfil a request.

Requirements: 3.1, 3.2, 3.4
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from forge.core.errors import ProviderUnavailableError

__all__ = [
    "CompletionRequest",
    "CompletionResponse",
    "LLMProvider",
    "ProviderUnavailableError",
]


class CompletionRequest(BaseModel):
    """Backend-agnostic request envelope for LLM completion calls.

    Attributes:
        prompt: The user prompt forwarded to the provider.
        max_tokens: Maximum number of tokens the provider may generate.
        temperature: Sampling temperature; 0.0 yields deterministic output.
        system: Optional system prompt that conditions the model.
        stop: Optional list of stop sequences that terminate generation.
    """

    prompt: str
    max_tokens: int = Field(default=512, ge=1)
    temperature: float = Field(default=0.0, ge=0.0)
    system: str | None = None
    stop: list[str] | None = None


class CompletionResponse(BaseModel):
    """Backend-agnostic response envelope returned from LLM completion calls.

    Attributes:
        text: The generated completion text.
        model_id: Identifier of the model that produced the response.
        prompt_tokens: Number of tokens consumed by the prompt.
        completion_tokens: Number of tokens produced as completion.
        latency_ms: Wall-clock latency of the inference call in milliseconds.
    """

    text: str
    model_id: str
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    latency_ms: float = Field(ge=0.0)


@runtime_checkable
class LLMProvider(Protocol):
    """Backend-agnostic LLM inference interface.

    All concrete providers (llama-cpp-python, Ollama, vLLM, OpenAI-compatible)
    implement this protocol so agent code can invoke inference without exposing
    backend-specific parameters. The Provider Abstraction Layer enforces a
    5-second timeout on each call (sourced from FORGE_PROVIDER_TIMEOUT) and
    raises ``ProviderUnavailableError`` when the configured backend fails to
    respond in time.
    """

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Generate a text completion for the given request.

        Args:
            request: The completion request envelope.

        Returns:
            A CompletionResponse with the generated text and accounting metadata.

        Raises:
            ProviderUnavailableError: If the backend fails to respond within the
                configured timeout (default 5 seconds via FORGE_PROVIDER_TIMEOUT)
                or otherwise cannot fulfil the request.
        """
        ...

    async def structured_output(
        self, request: CompletionRequest, schema: dict[str, object]
    ) -> dict[str, object]:
        """Generate a structured (JSON) response constrained by a schema.

        Args:
            request: The completion request envelope.
            schema: A JSON Schema describing the expected output shape.

        Returns:
            A dict matching the supplied schema.

        Raises:
            ProviderUnavailableError: If the backend fails to respond within the
                configured timeout or cannot produce schema-conformant output.
        """
        ...

    async def embed(self, text: str) -> list[float]:
        """Return a vector embedding for the given text.

        Args:
            text: The input text to embed.

        Returns:
            A list of floats representing the embedding vector.

        Raises:
            ProviderUnavailableError: If the backend fails to respond within the
                configured timeout or cannot produce an embedding.
        """
        ...

    async def health_check(self) -> bool:
        """Return True if the provider is operational.

        Used at startup and by health-check endpoints to confirm the backend
        is loaded and able to serve inference requests.
        """
        ...
