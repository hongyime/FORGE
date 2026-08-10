"""
forge/providers/bedrock_anthropic.py - AWS Bedrock + Anthropic message format.

Talks to Bedrock's ``InvokeModel`` API using boto3. Auto-detects the best
inference profile in the user's configured AWS region (preferring Haiku
profiles for executor-tier and Sonnet/Opus profiles for planner-tier).

Detection requires:
    * boto3 importable
    * ``~/.aws/credentials`` valid OR AWS env vars set
    * ``bedrock list-foundation-models`` returning at least one Anthropic
      model in the configured region

The config layer handles auto-discovery; this class accepts an explicit
``model_id`` (must be an inference-profile ARN or ID for on-demand-blocked
models like Haiku 4.5).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from forge.core.errors import ProviderUnavailableError
from forge.providers.base import (
    CompletionRequest,
    CompletionResponse,
)

__all__ = ["BedrockAnthropicProvider"]

_LOG = logging.getLogger(__name__)


class BedrockAnthropicProvider:
    """LLMProvider talking Anthropic message format on AWS Bedrock.

    Args:
        model_id: Bedrock model ID or inference profile ID. Examples:
            ``apac.anthropic.claude-3-haiku-20240307-v1:0`` (executor),
            ``us.anthropic.claude-haiku-4-5-20251001-v1:0`` (executor),
            ``global.anthropic.claude-haiku-4-5-20251001-v1:0`` (executor).
        region: AWS region, e.g. ``ap-southeast-1`` or ``us-east-1``.
            Defaults to the configured AWS profile region.
        timeout: Per-call wall-clock cap in seconds.
        boto3_client: Inject a pre-built client for tests.
    """

    def __init__(
        self,
        *,
        model_id: str,
        region: str | None = None,
        timeout: float = 30.0,
        boto3_client: Any = None,
    ) -> None:
        if not model_id:
            raise ValueError("BedrockAnthropicProvider requires model_id.")
        self._model_id = model_id
        self._region = region
        self._timeout = float(timeout)
        self._client = boto3_client

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def backend_name(self) -> str:
        return "bedrock_anthropic"

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3  # noqa: PLC0415
        except ImportError as exc:
            raise ProviderUnavailableError("bedrock_anthropic: boto3 not installed") from exc
        kwargs: dict[str, Any] = {"service_name": "bedrock-runtime"}
        if self._region:
            kwargs["region_name"] = self._region
        try:
            self._client = boto3.client(**kwargs)
        except Exception as exc:  # noqa: BLE001 - botocore raises various
            raise ProviderUnavailableError(
                f"bedrock_anthropic: failed to construct boto3 client: {exc}"
            ) from exc
        return self._client

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        body = self._build_request_body(request)
        t0 = time.perf_counter()
        try:
            client = self._get_client()
            # boto3 is sync; offload to a thread so we don't block the loop.
            resp = await asyncio.wait_for(
                asyncio.to_thread(
                    client.invoke_model,
                    modelId=self._model_id,
                    body=json.dumps(body),
                    contentType="application/json",
                    accept="application/json",
                ),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ProviderUnavailableError(
                f"bedrock_anthropic: timeout after {self._timeout}s"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - botocore raises various
            raise ProviderUnavailableError(f"bedrock_anthropic: invoke failed: {exc}") from exc

        try:
            payload = json.loads(resp["body"].read())
        except (KeyError, json.JSONDecodeError, AttributeError) as exc:
            raise ProviderUnavailableError(f"bedrock_anthropic: malformed response: {exc}") from exc

        text = self._extract_text(payload)
        usage = payload.get("usage") or {}
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return CompletionResponse(
            text=text,
            model_id=self._model_id,
            prompt_tokens=int(usage.get("input_tokens", 0)),
            completion_tokens=int(usage.get("output_tokens", 0)),
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
                f"schema:\n{json.dumps(schema)}"
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
                f"bedrock_anthropic: structured_output non-JSON: {text[:200]!r}"
            ) from exc

    async def embed(self, text: str) -> list[float]:
        raise ProviderUnavailableError(
            "bedrock_anthropic: embeddings via Anthropic models not supported; "
            "use a Cohere or Titan model via a separate provider."
        )

    async def health_check(self) -> bool:
        try:
            import boto3  # noqa: PLC0415
        except ImportError:
            return False
        try:
            kwargs: dict[str, Any] = {"service_name": "bedrock"}
            if self._region:
                kwargs["region_name"] = self._region
            bedrock = boto3.client(**kwargs)
            await asyncio.wait_for(
                asyncio.to_thread(bedrock.list_foundation_models),
                timeout=self._timeout,
            )
            return True
        except Exception:  # noqa: BLE001 - any error => unhealthy
            return False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_request_body(self, request: CompletionRequest) -> dict[str, Any]:
        body: dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": int(request.max_tokens),
            "temperature": float(request.temperature),
            "messages": [{"role": "user", "content": request.prompt}],
        }
        if request.system:
            body["system"] = request.system
        if request.stop:
            body["stop_sequences"] = list(request.stop)
        return body

    @staticmethod
    def _extract_text(payload: dict[str, Any]) -> str:
        content = payload.get("content")
        if not isinstance(content, list) or not content:
            raise ProviderUnavailableError(
                f"bedrock_anthropic: missing content array in response: {payload!r}"
            )
        # Anthropic returns a list of content blocks; concatenate text blocks.
        chunks: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                t = block.get("text")
                if isinstance(t, str):
                    chunks.append(t)
        if not chunks:
            raise ProviderUnavailableError(
                f"bedrock_anthropic: no text blocks in response: {content!r}"
            )
        return "".join(chunks)
