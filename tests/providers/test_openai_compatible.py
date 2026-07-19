"""
tests/providers/test_openai_compatible.py - Universal OpenAI-shaped client tests.

Covers the production code paths against a mocked HTTP transport:

    * Happy path - chat completion returns text + tokens
    * Health check 200 / 5xx
    * Timeout -> ProviderUnavailableError
    * 4xx -> ProviderUnavailableError with status preview
    * Malformed JSON -> ProviderUnavailableError
    * Missing 'choices' -> ProviderUnavailableError
    * Embeddings happy path
    * Embeddings malformed -> ProviderUnavailableError
    * structured_output strict mode
    * structured_output fallback when strict mode rejected
    * Backend-name auto-derivation per endpoint host
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from forge.core.errors import ProviderUnavailableError
from forge.providers.base import CompletionRequest
from forge.providers.openai_compatible import OpenAICompatibleProvider


def _make_provider(
    transport: httpx.MockTransport,
    *,
    endpoint: str = "https://api.example.com/v1",
    model: str = "test-model",
    api_key: str = "test-key",
) -> OpenAICompatibleProvider:
    client = httpx.AsyncClient(transport=transport, timeout=5.0)
    return OpenAICompatibleProvider(
        endpoint=endpoint,
        model=model,
        api_key=api_key,
        timeout=5.0,
        http_client=client,
    )


def _chat_response(text: str = "hello", model: str = "test-model") -> dict[str, Any]:
    return {
        "id": "chatcmpl-test",
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
    }


@pytest.mark.asyncio
async def test_complete_happy_path() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        captured["auth"] = request.headers.get("authorization", "")
        return httpx.Response(200, json=_chat_response("hello world"))

    p = _make_provider(httpx.MockTransport(handler))
    resp = await p.complete(CompletionRequest(prompt="hi", max_tokens=10))
    assert resp.text == "hello world"
    assert resp.model_id == "test-model"
    assert resp.prompt_tokens == 5
    assert resp.completion_tokens == 2
    assert captured["url"].endswith("/chat/completions")
    assert captured["body"]["model"] == "test-model"
    assert captured["body"]["messages"][-1]["content"] == "hi"
    assert captured["auth"] == "Bearer test-key"
    await p.aclose()


@pytest.mark.asyncio
async def test_complete_with_system_prompt() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        # System message must come first when set.
        assert body["messages"][0]["role"] == "system"
        assert body["messages"][0]["content"] == "you are forge"
        return httpx.Response(200, json=_chat_response())

    p = _make_provider(httpx.MockTransport(handler))
    await p.complete(CompletionRequest(prompt="x", system="you are forge"))
    await p.aclose()


@pytest.mark.asyncio
async def test_health_check_200() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": []})

    p = _make_provider(httpx.MockTransport(handler))
    assert await p.health_check() is True
    await p.aclose()


@pytest.mark.asyncio
async def test_health_check_5xx_returns_false() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream down")

    p = _make_provider(httpx.MockTransport(handler))
    assert await p.health_check() is False
    await p.aclose()


@pytest.mark.asyncio
async def test_complete_4xx_raises_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "invalid api key"}})

    p = _make_provider(httpx.MockTransport(handler))
    with pytest.raises(ProviderUnavailableError, match="HTTP 401"):
        await p.complete(CompletionRequest(prompt="x"))
    await p.aclose()


@pytest.mark.asyncio
async def test_complete_5xx_raises_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="bad gateway")

    p = _make_provider(httpx.MockTransport(handler))
    with pytest.raises(ProviderUnavailableError, match="HTTP 502"):
        await p.complete(CompletionRequest(prompt="x"))
    await p.aclose()


@pytest.mark.asyncio
async def test_complete_timeout_raises_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("simulated timeout")

    p = _make_provider(httpx.MockTransport(handler))
    with pytest.raises(ProviderUnavailableError, match="timeout"):
        await p.complete(CompletionRequest(prompt="x"))
    await p.aclose()


@pytest.mark.asyncio
async def test_complete_malformed_json_raises_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json at all")

    p = _make_provider(httpx.MockTransport(handler))
    with pytest.raises(ProviderUnavailableError, match="not JSON"):
        await p.complete(CompletionRequest(prompt="x"))
    await p.aclose()


@pytest.mark.asyncio
async def test_complete_missing_choices_raises_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "x", "usage": {}})

    p = _make_provider(httpx.MockTransport(handler))
    with pytest.raises(ProviderUnavailableError, match="choices"):
        await p.complete(CompletionRequest(prompt="x"))
    await p.aclose()


@pytest.mark.asyncio
async def test_embed_happy_path() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["input"] == "embed me"
        return httpx.Response(200, json={
            "data": [{"embedding": [0.1, 0.2, 0.3], "index": 0}]
        })

    p = _make_provider(httpx.MockTransport(handler))
    vec = await p.embed("embed me")
    assert vec == [0.1, 0.2, 0.3]
    await p.aclose()


@pytest.mark.asyncio
async def test_embed_malformed_raises_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": []})

    p = _make_provider(httpx.MockTransport(handler))
    with pytest.raises(ProviderUnavailableError, match="malformed embedding"):
        await p.embed("x")
    await p.aclose()


@pytest.mark.asyncio
async def test_structured_output_strict_mode() -> None:
    captured_body: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_body.update(json.loads(request.content))
        return httpx.Response(200, json=_chat_response('{"answer": 42}'))

    p = _make_provider(httpx.MockTransport(handler))
    out = await p.structured_output(
        CompletionRequest(prompt="give me 42"),
        {"type": "object", "properties": {"answer": {"type": "integer"}}},
    )
    assert out == {"answer": 42}
    assert captured_body["response_format"]["type"] == "json_schema"
    await p.aclose()


@pytest.mark.asyncio
async def test_structured_output_falls_back_when_strict_rejected() -> None:
    """Older endpoints / Ollama reject ``response_format``; we retry without."""
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        body = json.loads(request.content)
        if "response_format" in body:
            # First call: reject strict mode.
            return httpx.Response(400, json={"error": {"message": "unsupported"}})
        # Fallback call: accept and return JSON content.
        return httpx.Response(200, json=_chat_response('{"answer": 7}'))

    p = _make_provider(httpx.MockTransport(handler))
    out = await p.structured_output(
        CompletionRequest(prompt="give me 7"),
        {"type": "object", "properties": {"answer": {"type": "integer"}}},
    )
    assert out == {"answer": 7}
    assert call_count["n"] == 2
    await p.aclose()


@pytest.mark.asyncio
async def test_structured_output_non_json_response_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_chat_response("this is not json"))

    p = _make_provider(httpx.MockTransport(handler))
    with pytest.raises(ProviderUnavailableError, match="non-JSON"):
        await p.structured_output(
            CompletionRequest(prompt="x"),
            {"type": "object"},
        )
    await p.aclose()


@pytest.mark.asyncio
async def test_no_api_key_omits_authorization_header() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization", "<absent>")
        return httpx.Response(200, json=_chat_response())

    p = _make_provider(httpx.MockTransport(handler), api_key="")
    await p.complete(CompletionRequest(prompt="x"))
    assert captured["auth"] == "<absent>"
    await p.aclose()


@pytest.mark.asyncio
async def test_extra_headers_forwarded() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["referer"] = request.headers.get("http-referer", "")
        return httpx.Response(200, json=_chat_response())

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, timeout=5.0)
    p = OpenAICompatibleProvider(
        endpoint="https://openrouter.ai/api/v1",
        model="anthropic/claude-haiku-4-5",
        api_key="sk-or-v1-test",
        timeout=5.0,
        http_client=client,
        extra_headers={"HTTP-Referer": "https://forge.example/"},
    )
    await p.complete(CompletionRequest(prompt="x"))
    assert captured["referer"] == "https://forge.example/"
    await p.aclose()


# -- Backend-name auto-derivation --------------------------------------------


@pytest.mark.parametrize("endpoint,expected", [
    ("https://api.openai.com/v1", "openai"),
    ("https://openrouter.ai/api/v1", "openrouter"),
    ("https://api.groq.com/openai/v1", "groq"),
    ("https://api.deepseek.com/v1", "deepseek"),
    ("https://api.mistral.ai/v1", "mistral"),
    ("https://api.together.xyz/v1", "together"),
    ("https://api.fireworks.ai/inference/v1", "fireworks"),
    ("https://api.x.ai/v1", "xai"),
    ("https://api.perplexity.ai", "perplexity"),
    ("http://localhost:11434/v1", "ollama"),
    ("http://127.0.0.1:11434/v1", "ollama"),
    ("http://localhost:1234/v1", "lmstudio"),
    ("http://localhost:8080/v1", "llamacpp_server"),
    ("http://localhost:8000/v1", "vllm"),
])
def test_backend_name_auto_derivation(endpoint: str, expected: str) -> None:
    p = OpenAICompatibleProvider(endpoint=endpoint, model="x", api_key="k")
    assert p.backend_name == expected


def test_construction_rejects_empty_endpoint() -> None:
    with pytest.raises(ValueError):
        OpenAICompatibleProvider(endpoint="", model="x", api_key="k")


def test_construction_rejects_empty_model() -> None:
    with pytest.raises(ValueError):
        OpenAICompatibleProvider(endpoint="https://x", model="", api_key="k")
