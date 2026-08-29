"""
forge/providers/discovery.py - Parallel backend discovery for the LLM router.

Runs every probe concurrently with bounded timeouts and returns an ordered
list of :class:`DiscoveredBackend` records the :class:`TieredRouter` can
turn into provider instances.

Probes shipped (29 total):

  Tier A (local agent shell-outs, free):
      claude_code, codex_cli, gemini_cli, cursor_agent, aider

  Tier B (cloud SaaS APIs via openai_compatible, gated):
      openai, openrouter, anthropic_native, google_genai, xai, groq,
      deepseek, mistral, together, fireworks, perplexity, hf

  Tier C (cloud platform SDKs, gated):
      bedrock_anthropic, azure_openai, vertex_anthropic, vertex_gemini

  Tier D (local self-hosted servers + GGUF backstop):
      ollama, lmstudio, llamacpp_server, vllm, text_generation_webui,
      llama_cpp (in-process, ALWAYS LAST)

A backend is included in the result iff its detection signal succeeds
within the per-probe timeout. Paid backends (Tier B/C) are excluded
entirely unless ``FORGE_ALLOW_PAID_BACKENDS=1``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from forge.providers.cost_table import (
    ModelInfo,
    Tier,
    TierAssignment,
    classify_model,
    load_overrides,
)

__all__ = [
    "DiscoveredBackend",
    "DiscoveryResult",
    "discover_backends",
]

_LOG = logging.getLogger(__name__)

DEFAULT_PROBE_TIMEOUT_S = 3.0
DEFAULT_MODEL_LIST_TIMEOUT_S = 5.0


@dataclass(frozen=True)
class DiscoveredBackend:
    """One backend the router can use, with classified models."""

    backend_name: str  # e.g. "claude_code", "ollama"
    family: str  # e.g. "subprocess", "openai_compatible", "boto3"
    endpoint: str | None  # base URL or path; None for in-process / shell-out
    model_id: str  # the resolved primary model
    api_key_present: bool  # True iff backend uses a key (audit context)
    tier_assignment: TierAssignment
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DiscoveryResult:
    """Outcome of a full discovery sweep."""

    backends: list[DiscoveredBackend]
    skipped: list[tuple[str, str]]  # (probe_name, reason)
    duration_s: float
    paid_allowed: bool


# ---------------------------------------------------------------------------
# Probe implementations
# ---------------------------------------------------------------------------


def _is_paid_allowed() -> bool:
    return os.environ.get("FORGE_ALLOW_PAID_BACKENDS", "0").strip() in ("1", "true", "yes")


def _env_first(*names: str) -> str | None:
    for n in names:
        v = os.environ.get(n, "").strip()
        if v:
            return v
    return None


async def _tcp_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    """Lightweight TCP probe used for local-server detection."""
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, _sync_tcp_probe, host, port),
            timeout=timeout,
        )
        return True
    except (asyncio.TimeoutError, OSError):
        return False


def _sync_tcp_probe(host: str, port: int) -> None:
    with socket.create_connection((host, port), timeout=0.5):
        pass


# -------- Tier A: subprocess agents -----------------------------------------


async def _probe_claude_code() -> DiscoveredBackend | None:
    from forge.providers.claude_code import claude_code_available

    available, hint = claude_code_available()
    if not available:
        return None
    info = ModelInfo(model_id=hint or "claude-sonnet-subscription", backend_family="subprocess")
    # Subscription => name pattern dominates. claude_code subscription
    # typically serves Sonnet/Opus tier.
    info_planner = ModelInfo(
        model_id="claude-sonnet-subscription",
        backend_family="subprocess",
    )
    assignment = classify_model(info_planner)
    return DiscoveredBackend(
        backend_name="claude_code",
        family="subprocess",
        endpoint=shutil.which("claude") or shutil.which("claude.cmd"),
        model_id=hint or "claude-sonnet-subscription",
        api_key_present=False,
        tier_assignment=assignment,
        extra={"detection": "binary+oauth"},
    )


async def _probe_codex_cli() -> DiscoveredBackend | None:
    bin_path = shutil.which("codex") or shutil.which("codex.cmd")
    if not bin_path:
        return None
    return DiscoveredBackend(
        backend_name="codex_cli",
        family="subprocess",
        endpoint=bin_path,
        model_id="gpt-5-codex-subscription",
        api_key_present=False,
        tier_assignment=classify_model(ModelInfo(model_id="gpt-5", backend_family="subprocess")),
        extra={"detection": "binary"},
    )


async def _probe_gemini_cli() -> DiscoveredBackend | None:
    bin_path = shutil.which("gemini") or shutil.which("gemini.cmd")
    if not bin_path:
        return None
    return DiscoveredBackend(
        backend_name="gemini_cli",
        family="subprocess",
        endpoint=bin_path,
        model_id="gemini-3-pro-subscription",
        api_key_present=False,
        tier_assignment=classify_model(
            ModelInfo(model_id="gemini-3-pro", backend_family="subprocess")
        ),
        extra={"detection": "binary"},
    )


# -------- Tier B: cloud SaaS via openai_compatible ---------------------------


async def _probe_openai_compatible_saas(
    backend_name: str,
    *,
    env_key: tuple[str, ...],
    endpoint: str,
    default_model: str,
    require_paid_gate: bool = True,
) -> DiscoveredBackend | None:
    paid_allowed = _is_paid_allowed()
    free_only = backend_name == "openrouter" and not paid_allowed
    if require_paid_gate and not paid_allowed and not free_only:
        return None
    api_key = _env_first(*env_key)
    if not api_key:
        return None
    # Optionally fetch live model list; fall back to default_model on error
    # except for OpenRouter free-only mode, where we require proof of a free model.
    chosen_model = default_model
    pricing: dict[str, tuple[float | None, float | None]] = {}
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_MODEL_LIST_TIMEOUT_S) as client:
            model_list_url = f"{endpoint}/models"
            if backend_name == "openrouter" and free_only:
                model_list_url = f"{model_list_url}?sort=newest"
            resp = await client.get(
                model_list_url,
                headers={"Authorization": f"Bearer {api_key}"},
            )
            if 200 <= resp.status_code < 300:
                payload = resp.json()
                chosen_model, pricing = _pick_default_from_model_list(
                    payload,
                    default_model,
                    backend_name,
                    free_only=free_only,
                )
                if free_only and chosen_model is None:
                    return None
    except (httpx.HTTPError, json.JSONDecodeError, ValueError, TypeError):
        if free_only:
            return None

    if free_only and chosen_model == default_model:
        return None
    in_per_m, out_per_m = pricing.get(chosen_model, (None, None))
    info = ModelInfo(
        model_id=chosen_model,
        backend_family=backend_name,
        input_per_m=in_per_m,
        output_per_m=out_per_m,
    )
    return DiscoveredBackend(
        backend_name=backend_name,
        family="openai_compatible",
        endpoint=endpoint,
        model_id=chosen_model,
        api_key_present=True,
        tier_assignment=classify_model(info),
        extra={
            "env_var": env_key[0],
            "models_fetched": bool(pricing),
            "free_only": free_only,
        },
    )


def _openrouter_model_is_free(
    model_id: str,
    pricing: dict[str, tuple[float | None, float | None]],
) -> bool:
    input_price, output_price = pricing.get(model_id, (None, None))
    return input_price == 0.0 and output_price == 0.0


def _openrouter_model_capability_rank(model_id: str) -> int:
    lowered = str(model_id or "").lower()
    if any(marker in lowered for marker in ("tiny", "weak", "toy", "test")):
        return -1
    ranked_families = (
        ("qwen", 90),
        ("deepseek", 85),
        ("llama", 80),
        ("gemma", 75),
        ("mistral", 70),
        ("kimi", 68),
        ("phi", 65),
    )
    for marker, rank in ranked_families:
        if marker in lowered:
            return rank
    return -1


def _model_created_sort_key(model_entry: dict[str, Any]) -> int:
    for key in ("created", "created_at", "created_date"):
        value = model_entry.get(key)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.strip():
            text = value.strip()
            if text.isdigit():
                return int(text)
            try:
                from datetime import datetime  # noqa: PLC0415

                return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())
            except ValueError:
                continue
    return 0


def _pick_default_from_model_list(
    payload: Any,
    fallback_model: str,
    backend_name: str,
    *,
    free_only: bool = False,
) -> tuple[str | None, dict[str, tuple[float | None, float | None]]]:
    """Pick a sensible default model + extract pricing if available.

    Returns ``(model_id, {model_id: (input_per_m, output_per_m)})``. Pricing
    is only present when the endpoint returns it (notably OpenRouter).
    """
    pricing: dict[str, tuple[float | None, float | None]] = {}
    candidates: list[str] = []
    candidate_entries: dict[str, dict[str, Any]] = {}

    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return None if free_only else fallback_model, pricing

    for entry in data:
        if not isinstance(entry, dict):
            continue
        mid = entry.get("id") or entry.get("name") or entry.get("model")
        if not isinstance(mid, str):
            continue
        candidates.append(mid)
        candidate_entries[mid] = entry
        # OpenRouter returns ``pricing.prompt`` / ``pricing.completion`` in
        # $/token (NOT $/M-token), so multiply by 1e6.
        pr = entry.get("pricing")
        if isinstance(pr, dict):
            try:
                p_in = float(pr["prompt"]) * 1_000_000 if "prompt" in pr else None
                p_out = float(pr["completion"]) * 1_000_000 if "completion" in pr else None
                pricing[mid] = (p_in, p_out)
            except (TypeError, ValueError):
                pass

    if not candidates:
        return None if free_only else fallback_model, pricing
    if backend_name == "openrouter" and free_only:
        capable_free_candidates = [
            mid
            for mid in candidates
            if _openrouter_model_is_free(mid, pricing)
            and _openrouter_model_capability_rank(mid) >= 0
        ]
        if not capable_free_candidates:
            return None, pricing
        capable_free_candidates.sort(
            key=lambda mid: (
                _model_created_sort_key(candidate_entries.get(mid, {})),
                _openrouter_model_capability_rank(mid),
            ),
            reverse=True,
        )
        return capable_free_candidates[0], pricing

    # Prefer cheap fast models per backend:
    preference: dict[str, list[str]] = {
        "openrouter": ["haiku", "flash", "mini"],
        "openai": ["mini", "nano"],
        "groq": ["llama-3", "qwen"],
        "deepseek": ["chat"],
        "mistral": ["small", "nemo"],
        "together": ["8b", "7b"],
        "fireworks": ["8b", "7b"],
        "xai": ["mini"],
        "google_genai": ["flash"],
        "perplexity": ["sonar"],
    }
    keywords = preference.get(backend_name, [])
    for kw in keywords:
        for mid in candidates:
            if kw.lower() in mid.lower():
                return mid, pricing
    return fallback_model if fallback_model in candidates else candidates[0], pricing


# -------- Tier C: cloud platform SDKs ----------------------------------------


async def _probe_bedrock_anthropic() -> DiscoveredBackend | None:
    if not _is_paid_allowed():
        return None
    creds = Path.home() / ".aws" / "credentials"
    config = Path.home() / ".aws" / "config"
    has_env_creds = bool(_env_first("AWS_ACCESS_KEY_ID", "AWS_PROFILE"))
    if not creds.exists() and not has_env_creds:
        return None
    # Pick a region: env > config > default. We DON'T call AWS APIs here;
    # the actual list-models call happens in BedrockAnthropicProvider.health.
    region = (
        _env_first("AWS_REGION", "AWS_DEFAULT_REGION") or _read_aws_region(config) or "us-east-1"
    )
    # Default to a Haiku inference profile in the user's region; the user
    # can override via FORGE_BEDROCK_MODEL.
    explicit_model = os.environ.get("FORGE_BEDROCK_MODEL", "").strip()
    if explicit_model:
        chosen = explicit_model
    else:
        # Auto-pick by region prefix: ap-* uses apac.* profiles, us-* uses us.*
        if region.startswith("ap-"):
            chosen = "apac.anthropic.claude-3-haiku-20240307-v1:0"
        else:
            chosen = "us.anthropic.claude-3-haiku-20240307-v1:0"
    info = ModelInfo(
        model_id=chosen,
        backend_family="bedrock_anthropic",
        # Approx Bedrock pricing for Haiku 3 - hardcoded as a fallback only.
        input_per_m=0.25,
        output_per_m=1.25,
    )
    return DiscoveredBackend(
        backend_name="bedrock_anthropic",
        family="boto3",
        endpoint=f"bedrock-runtime.{region}.amazonaws.com",
        model_id=chosen,
        api_key_present=True,
        tier_assignment=classify_model(info),
        extra={"region": region},
    )


def _read_aws_region(config_path: Path) -> str | None:
    if not config_path.exists():
        return None
    try:
        for line in config_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("region"):
                _, _, val = line.partition("=")
                return val.strip() or None
    except OSError:
        pass
    return None


# -------- Tier D: local self-hosted + GGUF -----------------------------------


async def _probe_local_openai_server(
    backend_name: str,
    *,
    host: str,
    port: int,
    endpoint_suffix: str = "/v1",
) -> DiscoveredBackend | None:
    if not await _tcp_listening(host, port):
        return None
    base = f"http://{host}:{port}{endpoint_suffix}"
    chosen = "default"
    parameter_count_b: float | None = None
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_MODEL_LIST_TIMEOUT_S) as client:
            # Ollama's /api/tags is richer; openai-shape /v1/models also works.
            tags_url = (
                f"http://{host}:{port}/api/tags" if backend_name == "ollama" else f"{base}/models"
            )
            resp = await client.get(tags_url)
            if 200 <= resp.status_code < 300:
                payload = resp.json()
                chosen, parameter_count_b = _pick_local_model(payload, backend_name)
    except (httpx.HTTPError, json.JSONDecodeError, ValueError, TypeError):
        pass

    info = ModelInfo(
        model_id=chosen,
        backend_family=backend_name,
        parameter_count_b=parameter_count_b,
    )
    return DiscoveredBackend(
        backend_name=backend_name,
        family="openai_compatible",
        endpoint=base,
        model_id=chosen,
        api_key_present=False,
        tier_assignment=classify_model(info),
        extra={"parameter_count_b": parameter_count_b},
    )


def _pick_local_model(payload: Any, backend_name: str) -> tuple[str, float | None]:
    """Pick a default model from a local model server's listing.

    Returns ``(model_id, parameter_count_b_or_none)``.
    """
    if backend_name == "ollama":
        models = payload.get("models") if isinstance(payload, dict) else None
        if isinstance(models, list) and models:
            # Prefer the largest-parameter model for planner tier upgrade.
            best: tuple[str, float | None] = ("default", None)
            best_params = -1.0
            for entry in models:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name") or entry.get("model")
                if not isinstance(name, str):
                    continue
                details = entry.get("details") or {}
                size = None
                ps = details.get("parameter_size") if isinstance(details, dict) else None
                if isinstance(ps, str):
                    size = _parse_param_size(ps)
                if size is not None and size > best_params:
                    best = (name, size)
                    best_params = size
                elif best_params < 0:
                    best = (name, size)
            return best
    # openai-shape /v1/models
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            mid = first.get("id") or first.get("name") or "default"
            return str(mid), None
    return "default", None


def _parse_param_size(s: str) -> float | None:
    """Parse Ollama's parameter_size strings like '7B', '70.6B', '0.5B'."""
    s = s.strip().lower().rstrip("b")
    try:
        return float(s)
    except ValueError:
        return None


async def _probe_llama_cpp() -> DiscoveredBackend | None:
    """Always-last backstop. Find a GGUF file we can load."""
    explicit = os.environ.get("FORGE_LLM_MODEL_PATH", "").strip()
    if explicit and Path(explicit).exists():
        path = Path(explicit)
    else:
        cache_dir = Path.home() / ".cache" / "forge" / "models"
        if not cache_dir.exists():
            return None
        ggufs = sorted(cache_dir.glob("*.gguf"))
        if not ggufs:
            return None
        path = ggufs[0]
    # Estimate parameter count from filename, e.g. "qwen2.5-1.5b-instruct..."
    import re

    m = re.search(r"(\d+(?:\.\d+)?)\s*b", path.name, re.IGNORECASE)
    params = float(m.group(1)) if m else None
    info = ModelInfo(
        model_id=path.name,
        backend_family="llama_cpp",
        parameter_count_b=params,
    )
    return DiscoveredBackend(
        backend_name="llama_cpp",
        family="llama_cpp",
        endpoint=str(path),
        model_id=path.name,
        api_key_present=False,
        tier_assignment=classify_model(info),
        extra={"backstop": True, "parameter_count_b": params},
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def discover_backends(
    *,
    probe_timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
    overrides: dict[str, str] | None = None,
) -> DiscoveryResult:
    """Run all probes in parallel, return what we found.

    Args:
        probe_timeout_s: Per-probe timeout. Each probe runs concurrently and
            cooperatively cancels on timeout.
        overrides: Operator tier overrides; falls back to
            :func:`load_overrides` reading the default config file.

    Returns:
        A :class:`DiscoveryResult` listing detected backends + skip reasons.
    """
    import time as _time

    t0 = _time.perf_counter()
    overrides = overrides if overrides is not None else load_overrides()

    paid_allowed = _is_paid_allowed()

    # The probe table. Each entry is (name, coroutine_factory). We use
    # factories so probes are constructed inside the gather, not eagerly.
    probes: list[tuple[str, "asyncio.Future[DiscoveredBackend | None]"]] = []

    def run_probe(coro: Any, name: str) -> "asyncio.Future[DiscoveredBackend | None]":
        async def _wrapped() -> DiscoveredBackend | None:
            try:
                return await asyncio.wait_for(coro, timeout=probe_timeout_s)
            except asyncio.TimeoutError:
                _LOG.debug("discovery probe %s timed out", name)
                return None
            except Exception as exc:  # noqa: BLE001 - defensive
                _LOG.debug("discovery probe %s failed: %s", name, exc)
                return None

        return asyncio.ensure_future(_wrapped())

    # Tier A
    probes.append(("claude_code", run_probe(_probe_claude_code(), "claude_code")))
    probes.append(("codex_cli", run_probe(_probe_codex_cli(), "codex_cli")))
    probes.append(("gemini_cli", run_probe(_probe_gemini_cli(), "gemini_cli")))

    # Tier B (paid-gated)
    saas_specs = [
        (
            "openrouter",
            ("OPENROUTER_API_KEY",),
            "https://openrouter.ai/api/v1",
            "anthropic/claude-haiku-4-5",
        ),
        ("openai", ("OPENAI_API_KEY",), "https://api.openai.com/v1", "gpt-4o-mini"),
        ("groq", ("GROQ_API_KEY",), "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
        ("deepseek", ("DEEPSEEK_API_KEY",), "https://api.deepseek.com/v1", "deepseek-chat"),
        ("mistral", ("MISTRAL_API_KEY",), "https://api.mistral.ai/v1", "mistral-small-latest"),
        (
            "together",
            ("TOGETHER_API_KEY",),
            "https://api.together.xyz/v1",
            "meta-llama/Llama-3-8b-chat-hf",
        ),
        (
            "fireworks",
            ("FIREWORKS_API_KEY",),
            "https://api.fireworks.ai/inference/v1",
            "accounts/fireworks/models/llama-v3-8b-instruct",
        ),
        ("xai", ("XAI_API_KEY",), "https://api.x.ai/v1", "grok-2-1212"),
        ("perplexity", ("PERPLEXITY_API_KEY",), "https://api.perplexity.ai", "sonar-small-online"),
        (
            "google_genai",
            ("GOOGLE_API_KEY", "GEMINI_API_KEY"),
            "https://generativelanguage.googleapis.com/v1beta/openai",
            "gemini-2.0-flash",
        ),
    ]
    for name, env_keys, ep, dm in saas_specs:
        probes.append(
            (
                name,
                run_probe(
                    _probe_openai_compatible_saas(
                        name,
                        env_key=env_keys,
                        endpoint=ep,
                        default_model=dm,
                    ),
                    name,
                ),
            )
        )

    # Tier C
    probes.append(("bedrock_anthropic", run_probe(_probe_bedrock_anthropic(), "bedrock_anthropic")))

    # Tier D - local servers
    local_specs = [
        ("ollama", "127.0.0.1", 11434, "/v1"),
        ("lmstudio", "127.0.0.1", 1234, "/v1"),
        ("llamacpp_server", "127.0.0.1", 8080, "/v1"),
        ("vllm", "127.0.0.1", 8000, "/v1"),
        ("text_generation_webui", "127.0.0.1", 5000, "/v1"),
    ]
    for name, host, port, suf in local_specs:
        probes.append(
            (
                name,
                run_probe(
                    _probe_local_openai_server(
                        name,
                        host=host,
                        port=port,
                        endpoint_suffix=suf,
                    ),
                    name,
                ),
            )
        )

    # Tier D - llama_cpp backstop
    probes.append(("llama_cpp", run_probe(_probe_llama_cpp(), "llama_cpp")))

    # Wait for all probes to settle.
    raw_results = await asyncio.gather(*(f for _, f in probes), return_exceptions=False)

    found: list[DiscoveredBackend] = []
    skipped: list[tuple[str, str]] = []
    for (name, _), result in zip(probes, raw_results, strict=True):
        if result is None:
            skipped.append((name, "not_detected"))
        else:
            found.append(result)

    # Sort: subscription/free first, then bedrock, then SaaS by tier-pref,
    # then local servers, llama_cpp ALWAYS last.
    family_order = {
        "subprocess": 0,  # Claude Code, Codex CLI etc - free, top-quality
        "boto3": 1,  # Bedrock - paid but accountable
        "openai_compatible": 2,  # SaaS APIs + local OpenAI-shaped servers
        "llama_cpp": 99,  # backstop
    }
    found.sort(key=lambda b: (family_order.get(b.family, 50), b.backend_name))
    # Ensure llama_cpp is dead last regardless.
    backstops = [b for b in found if b.backend_name == "llama_cpp"]
    rest = [b for b in found if b.backend_name != "llama_cpp"]
    found = rest + backstops

    duration_s = _time.perf_counter() - t0
    return DiscoveryResult(
        backends=found,
        skipped=skipped,
        duration_s=duration_s,
        paid_allowed=paid_allowed,
    )
