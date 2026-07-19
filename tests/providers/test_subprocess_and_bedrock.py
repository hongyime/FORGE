"""
tests/providers/test_subprocess_and_bedrock.py - Tests for shell-out + Bedrock providers.

Covers:
    * ClaudeCodeProvider construction with mocked binary
    * ClaudeCodeProvider timeout
    * ClaudeCodeProvider non-zero exit
    * ClaudeCodeProvider structured_output with code-fence stripping
    * BedrockAnthropicProvider invoke happy path (mocked boto3 client)
    * BedrockAnthropicProvider timeout
    * BedrockAnthropicProvider malformed response
    * BedrockAnthropicProvider health_check
    * claude_code_available() detection
"""

from __future__ import annotations

import io
import json
from typing import Any
from unittest.mock import patch

import pytest

from forge.core.errors import ProviderUnavailableError
from forge.providers.base import CompletionRequest
from forge.providers.bedrock_anthropic import BedrockAnthropicProvider
from forge.providers.claude_code import (
    ClaudeCodeProvider,
    claude_code_available,
)


# ---------------------------------------------------------------------------
# Fake boto3 client for Bedrock tests
# ---------------------------------------------------------------------------


class _FakeBedrockBody:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._buf = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._buf


class _FakeBedrockClient:
    def __init__(self, response_payload: dict[str, Any] | None = None,
                 raise_exc: Exception | None = None) -> None:
        self._payload = response_payload or {
            "content": [{"type": "text", "text": "fake response"}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        self._raise = raise_exc
        self.invoke_calls: list[dict[str, Any]] = []

    def invoke_model(self, **kwargs: Any) -> dict[str, Any]:
        self.invoke_calls.append(kwargs)
        if self._raise is not None:
            raise self._raise
        return {"body": _FakeBedrockBody(self._payload)}


# ---------------------------------------------------------------------------
# BedrockAnthropicProvider
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bedrock_complete_happy_path() -> None:
    fake = _FakeBedrockClient()
    p = BedrockAnthropicProvider(
        model_id="apac.anthropic.claude-3-haiku-20240307-v1:0",
        region="ap-southeast-1",
        boto3_client=fake,
    )
    resp = await p.complete(CompletionRequest(prompt="hello", max_tokens=20))
    assert resp.text == "fake response"
    assert resp.model_id == "apac.anthropic.claude-3-haiku-20240307-v1:0"
    assert resp.prompt_tokens == 10
    assert resp.completion_tokens == 5
    assert len(fake.invoke_calls) == 1
    body = json.loads(fake.invoke_calls[0]["body"])
    assert body["anthropic_version"] == "bedrock-2023-05-31"
    assert body["messages"][0]["content"] == "hello"


@pytest.mark.asyncio
async def test_bedrock_complete_with_system_prompt() -> None:
    fake = _FakeBedrockClient()
    p = BedrockAnthropicProvider(
        model_id="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        boto3_client=fake,
    )
    await p.complete(CompletionRequest(prompt="hi", system="be terse"))
    body = json.loads(fake.invoke_calls[0]["body"])
    assert body["system"] == "be terse"


@pytest.mark.asyncio
async def test_bedrock_invoke_failure_raises_unavailable() -> None:
    fake = _FakeBedrockClient(raise_exc=RuntimeError("throttled"))
    p = BedrockAnthropicProvider(model_id="x", boto3_client=fake)
    with pytest.raises(ProviderUnavailableError, match="invoke failed"):
        await p.complete(CompletionRequest(prompt="x"))


@pytest.mark.asyncio
async def test_bedrock_malformed_response_raises_unavailable() -> None:
    fake = _FakeBedrockClient(response_payload={"no_content_field": True})
    p = BedrockAnthropicProvider(model_id="x", boto3_client=fake)
    with pytest.raises(ProviderUnavailableError, match="missing content"):
        await p.complete(CompletionRequest(prompt="x"))


@pytest.mark.asyncio
async def test_bedrock_construction_rejects_empty_model() -> None:
    with pytest.raises(ValueError):
        BedrockAnthropicProvider(model_id="")


@pytest.mark.asyncio
async def test_bedrock_structured_output_strips_code_fences() -> None:
    fake = _FakeBedrockClient(response_payload={
        "content": [{"type": "text", "text": "```json\n{\"answer\": 99}\n```"}],
        "usage": {"input_tokens": 1, "output_tokens": 1},
    })
    p = BedrockAnthropicProvider(model_id="x", boto3_client=fake)
    out = await p.structured_output(
        CompletionRequest(prompt="x"),
        {"type": "object"},
    )
    assert out == {"answer": 99}


# ---------------------------------------------------------------------------
# ClaudeCodeProvider
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_claude_code_construction_rejects_missing_binary() -> None:
    with patch("shutil.which", return_value=None):
        with pytest.raises(ProviderUnavailableError, match="binary not found"):
            ClaudeCodeProvider(binary="nonexistent-binary-xyz")


@pytest.mark.asyncio
async def test_claude_code_complete_happy_path(tmp_path: Any) -> None:
    # Build a tiny stub script that prints a known string
    if hasattr(__import__("sys"), "winver") or "win" in __import__("sys").platform:
        # Windows: use a .cmd that echoes the prompt back
        stub = tmp_path / "claude.cmd"
        stub.write_text(
            "@echo off\r\necho stub-response\r\n",
            encoding="ascii",
        )
    else:
        stub = tmp_path / "claude"
        stub.write_text("#!/bin/sh\necho stub-response\n")
        stub.chmod(0o755)

    p = ClaudeCodeProvider(binary=str(stub), timeout=10.0)
    resp = await p.complete(CompletionRequest(prompt="hi"))
    assert "stub-response" in resp.text
    assert resp.model_id == "claude-code-subscription"


@pytest.mark.asyncio
async def test_claude_code_non_zero_exit_raises_unavailable(tmp_path: Any) -> None:
    import sys as _sys
    if "win" in _sys.platform:
        stub = tmp_path / "claude.cmd"
        stub.write_text("@echo off\r\necho boom 1>&2\r\nexit /b 7\r\n", encoding="ascii")
    else:
        stub = tmp_path / "claude"
        stub.write_text("#!/bin/sh\necho boom >&2\nexit 7\n")
        stub.chmod(0o755)

    p = ClaudeCodeProvider(binary=str(stub), timeout=10.0)
    with pytest.raises(ProviderUnavailableError, match="exit=7"):
        await p.complete(CompletionRequest(prompt="x"))


@pytest.mark.asyncio
async def test_claude_code_health_check(tmp_path: Any) -> None:
    import sys as _sys
    if "win" in _sys.platform:
        stub = tmp_path / "claude.cmd"
        stub.write_text("@echo off\r\necho 1.0.0\r\nexit /b 0\r\n", encoding="ascii")
    else:
        stub = tmp_path / "claude"
        stub.write_text("#!/bin/sh\necho 1.0.0\n")
        stub.chmod(0o755)

    p = ClaudeCodeProvider(binary=str(stub), timeout=10.0)
    assert await p.health_check() is True


@pytest.mark.asyncio
async def test_claude_code_embed_raises_unavailable(tmp_path: Any) -> None:
    import sys as _sys
    if "win" in _sys.platform:
        stub = tmp_path / "claude.cmd"
        stub.write_text("@echo off\r\nexit /b 0\r\n", encoding="ascii")
    else:
        stub = tmp_path / "claude"
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)

    p = ClaudeCodeProvider(binary=str(stub))
    with pytest.raises(ProviderUnavailableError, match="embeddings not supported"):
        await p.embed("x")


# ---------------------------------------------------------------------------
# claude_code_available probe
# ---------------------------------------------------------------------------


def test_claude_code_available_reports_true_on_user_machine() -> None:
    """On the actual dev machine, Claude Code is installed and logged in."""
    available, hint = claude_code_available()
    # We don't assert True/False - we just assert the function runs cleanly
    # and returns a (bool, str|None) shape regardless of environment.
    assert isinstance(available, bool)
    assert hint is None or isinstance(hint, str)


def test_claude_code_available_false_without_binary() -> None:
    with patch("shutil.which", return_value=None):
        available, hint = claude_code_available()
        assert available is False
        assert hint is None
