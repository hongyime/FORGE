"""
forge/providers/openai_compatible.py - Universal OpenAI-shaped backend.

ONE provider class talks to anything that exposes OpenAI's
``/v1/chat/completions`` shape:

    * Ollama   (http://localhost:11434/v1)
    * OpenAI   (https://api.openai.com/v1)
    * Azure OpenAI (https://<resource>.openai.azure.com/openai/v1)
    * OpenRouter (https://openrouter.ai/api/v1)
    * Groq     (https://api.groq.com/openai/v1)
    * DeepSeek (https://api.deepseek.com/v1)
    * Mistral  (https://api.mistral.ai/v1)
    * Together (https://api.together.xyz/v1)
    * Fireworks (https://api.fireworks.ai/inference/v1)
    * xAI Grok (https://api.x.ai/v1)
    * Perplexity (https://api.perplexity.ai)
    * Hugging Face (https://api-inference.huggingface.co/v1)
    * LM Studio (http://localhost:1234/v1)
    * llama.cpp server (http://localhost:8080/v1)
    * vLLM     (http://localhost:8000/v1)
    * text-generation-webui (http://localhost:5000/v1)

A single class with one auth path, one timeout path, one retry-policy path.
Endpoint, model, and API key are passed in at construction; the rest is
identical across all 16 backends.

Conforms to :class:`forge.providers.base.LLMProvider` so the
:class:`FallbackChainProvider` and :class:`TieredRouter` can use it
interchangeably with native providers (``llama_cpp``, ``bedrock_anthropic``,
``anthropic_native``, ``claude_code``).
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx

from forge.core.errors import ProviderUnavailableError
from forge.providers.base import (
    CompletionRequest,
    CompletionResponse,
)

__all__ = ["OpenAICompatibleProvider"]

_LOG = logging.getLogger(__name__)

# Hard cap on response size (bytes). Defeats runaway responses that would
# exhaust memory or context limits downstream.
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024  # 4 MiB


class OpenAICompatibleProvider:
    """Generic LLMProvider talking the OpenAI Chat Completions REST shape.

    Args:
        endpoint: Base URL, e.g. ``http://localhost:11434/v1`` or
            ``https://api.openai.com/v1``. Trailing slash trimmed.
        model: Model identifier accepted by the endpoint, e.g.
            ``qwen2.5:0.5b``, ``gpt-4o-mini``,
            ``anthropic/claude-haiku-4-5``.
        api_key: Authorization bearer. Use ``"ollama"`` or any placeholder
            for endpoints that don't authenticate (Ollama, LM Studio, ...).
            Empty string means no Authorization header at all.
        timeout: Per-call wall clock cap in seconds.
        backend_name: Logical name for audit / health output, e.g.
            ``ollama``, ``openrouter``, ``openai``. Defaults to host.
        extra_headers: Optional headers (e.g. OpenRouter's HTTP-Referer).
        http_client: Inject a pre-built httpx.AsyncClient for testing.
    """

    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        api_key: str = "",
        timeout: float = 30.0,
        backend_name: str | None = None,
        extra_headers: dict[str, str] | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not endpoint:
            raise ValueError("OpenAICompatibleProvider requires endpoint.")
        if not model:
            raise ValueError("OpenAICompatibleProvider requires model.")
        self._endpoint = endpoint.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._timeout = float(timeout)
        self._backend_name = backend_name or self._derive_name(self._endpoint)
        self._extra_headers = dict(extra_headers or {})
        self._client = http_client
        self._client_owned = http_client is None

    # ------------------------------------------------------------------
    # Public read-only metadata
    # ------------------------------------------------------------------

    @property
    def model_id(self) -> str:
        return self._model

    @property
    def backend_name(self) -> str:
        return self._backend_name

    @property
    def endpoint(self) -> str:
        return self._endpoint

    # ------------------------------------------------------------------
    # LLMProvider protocol
    # ------------------------------------------------------------------

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        payload = self._build_chat_payload(request)
        body = await self._post_json("/chat/completions", payload)
        return self._parse_chat_response(body, t0=time.perf_counter())

    async def structured_output(
        self,
        request: CompletionRequest,
        schema: dict[str, object],
    ) -> dict[str, object]:
        """Use OpenAI's ``response_format=json_schema`` if the endpoint
        supports it; otherwise fall back to instructing the model to emit
        JSON and parsing the result.

        Conformance varies wildly across providers, so we try the strict
        path first and degrade gracefully on a 4xx.
        """
        # Strict mode (OpenAI-recent, OpenRouter for compatible models)
        strict_payload = self._build_chat_payload(request)
        strict_payload["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "forge_output", "schema": schema, "strict": True},
        }
        try:
            body = await self._post_json("/chat/completions", strict_payload)
        except ProviderUnavailableError:
            # Strict mode rejected (older models, Ollama, etc.). Retry with
            # a JSON-instructed prompt.
            instructed = CompletionRequest(
                prompt=(
                    f"{request.prompt}\n\n"
                    "Respond with ONLY valid JSON conforming to this schema:\n"
                    f"{json.dumps(schema)}"
                ),
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                system=request.system,
                stop=request.stop,
            )
            body = await self._post_json(
                "/chat/completions", self._build_chat_payload(instructed)
            )

        text = self._extract_message_text(body)
        try:
            return dict(json.loads(text))
        except (json.JSONDecodeError, TypeError) as exc:
            raise ProviderUnavailableError(
                f"{self._backend_name}: structured_output returned non-JSON: "
                f"{text[:200]!r} ({exc})"
            ) from exc

    async def embed(self, text: str) -> list[float]:
        body = await self._post_json(
            "/embeddings",
            {"model": self._model, "input": text},
        )
        try:
            data = body["data"]
            if not isinstance(data, list) or not data:
                raise KeyError("data")
            vec = data[0]["embedding"]
            if not isinstance(vec, list):
                raise TypeError("embedding not list")
            return [float(x) for x in vec]
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderUnavailableError(
                f"{self._backend_name}: malformed embedding response: {body!r}"
            ) from exc

    async def health_check(self) -> bool:
        """``GET /models`` returns a model list when the endpoint is alive.

        We don't validate that ``self._model`` is present in the list —
        some endpoints (Ollama with implicit pull, LM Studio with auto-load)
        are happy to serve unloaded models on first request, and we don't
        want a transient 'model not loaded yet' state to mark the backend
        unhealthy.
        """
        client = await self._ensure_client()
        try:
            resp = await client.get(
                f"{self._endpoint}/models",
                headers=self._headers(),
                timeout=self._timeout,
            )
            return 200 <= resp.status_code < 300
        except (httpx.HTTPError, httpx.TimeoutException):
            return False

    async def aclose(self) -> None:
        """Close the owned HTTP client if we created it."""
        if self._client is not None and self._client_owned:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_name(endpoint: str) -> str:
        """Infer a backend name from the endpoint host for audit logs."""
        host = httpx.URL(endpoint).host
        for needle, name in (
            ("openai.com", "openai"),
            ("openrouter.ai", "openrouter"),
            ("anthropic.com", "anthropic"),
            ("groq.com", "groq"),
            ("deepseek.com", "deepseek"),
            ("mistral.ai", "mistral"),
            ("together.xyz", "together"),
            ("fireworks.ai", "fireworks"),
            ("x.ai", "xai"),
            ("perplexity.ai", "perplexity"),
            ("huggingface", "huggingface"),
            ("openai.azure.com", "azure_openai"),
            ("vertexai.googleapis.com", "vertex"),
            ("googleapis.com", "google_genai"),
            ("localhost:11434", "ollama"),
            ("127.0.0.1:11434", "ollama"),
            ("localhost:1234", "lmstudio"),
            ("localhost:8080", "llamacpp_server"),
            ("localhost:8000", "vllm"),
            ("localhost:5000", "text_gen_webui"),
        ):
            if needle in endpoint:
                return name
        return host or "openai_compatible"

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        h.update(self._extra_headers)
        return h

    def _build_chat_payload(self, request: CompletionRequest) -> dict[str, Any]:
        messages: list[dict[str, str]] = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "max_tokens": int(request.max_tokens),
            "temperature": float(request.temperature),
        }
        if request.stop:
            payload["stop"] = list(request.stop)
        return payload

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                limits=httpx.Limits(
                    max_connections=20,
                    max_keepalive_connections=5,
                    keepalive_expiry=30.0,
                ),
                follow_redirects=False,
            )
            self._client_owned = True
        return self._client

    async def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._endpoint}{path}"
        client = await self._ensure_client()
        try:
            resp = await client.post(
                url,
                headers=self._headers(),
                json=payload,
                timeout=self._timeout,
            )
        except httpx.TimeoutException as exc:
            raise ProviderUnavailableError(
                f"{self._backend_name}: timeout after {self._timeout}s on {path}"
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderUnavailableError(
                f"{self._backend_name}: connection error on {path}: {exc}"
            ) from exc

        if resp.status_code >= 400:
            preview = resp.content[:200].decode("utf-8", errors="replace")
            raise ProviderUnavailableError(
                f"{self._backend_name}: HTTP {resp.status_code} on {path}: {preview!r}"
            )

        if len(resp.content) > _MAX_RESPONSE_BYTES:
            raise ProviderUnavailableError(
                f"{self._backend_name}: response exceeds "
                f"{_MAX_RESPONSE_BYTES} byte cap"
            )

        try:
            return dict(resp.json())
        except json.JSONDecodeError as exc:
            preview = resp.content[:200].decode("utf-8", errors="replace")
            raise ProviderUnavailableError(
                f"{self._backend_name}: response is not JSON: {preview!r}"
            ) from exc

    def _parse_chat_response(
        self, body: dict[str, Any], *, t0: float
    ) -> CompletionResponse:
        text = self._extract_message_text(body)
        usage = body.get("usage") or {}
        model_id = str(body.get("model") or self._model)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return CompletionResponse(
            text=text,
            model_id=model_id,
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            latency_ms=max(0.0, latency_ms),
        )

    @staticmethod
    def _extract_message_text(body: dict[str, Any]) -> str:
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderUnavailableError(
                f"missing or empty 'choices' in response: keys={list(body)}"
            )
        first = choices[0]
        if not isinstance(first, dict):
            raise ProviderUnavailableError(
                f"choices[0] not an object: {first!r}"
            )
        msg = first.get("message")
        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
            return str(msg["content"])
        # Some providers (older OpenAI completion endpoints, certain
        # LM Studio builds) return ``text`` instead of ``message.content``.
        if isinstance(first.get("text"), str):
            return str(first["text"])
        raise ProviderUnavailableError(
            f"unrecognised choice shape: {first!r}"
        )
