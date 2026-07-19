"""
tests/providers/test_cost_table.py - Tier classifier tests.

Verifies the heuristic tier classifier against:
    * known-planner models (opus, sonnet, gpt-5, o3, gemini-pro, large)
    * known-executor models (haiku, flash, mini, nano, 7b, codestral)
    * mid-priced models (live pricing)
    * parameter-count signals (local models)
    * operator overrides
    * unknown models -> safe default (both, executor-preferred)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from forge.providers.cost_table import (
    ModelInfo,
    Tier,
    classify_model,
    load_overrides,
)


def _info(model_id: str, **kw: object) -> ModelInfo:
    return ModelInfo(model_id=model_id, backend_family="test", **kw)  # type: ignore[arg-type]


# -- Planner via name pattern -------------------------------------------------


@pytest.mark.parametrize("model_id", [
    "claude-opus-4-7",
    "claude-opus-5",                # future-proof
    "anthropic.claude-opus-2026",   # future-proof
    "claude-sonnet-4-7",
    "claude-sonnet-9-future",       # future-proof
    "gpt-5",
    "gpt-6-turbo",                  # future-proof
    "o1-preview",
    "gemini-2-5-pro",
    "gemini-4-pro",                 # future-proof
    "vertex/gemini-pro",
    "deepseek-r1",
    "deepseek-r2",                  # future-proof
    "grok-3",
    "grok-9",                       # future-proof
    "mistral-large-2",
    "meta-llama-3-70b",
    "qwen-72b",
    "llama-405b",
    "sonar-pro",
])
def test_planner_patterns(model_id: str) -> None:
    a = classify_model(_info(model_id))
    import re as _re
    is_executor_pattern = bool(_re.search(r'\\b(?:mini|nano|micro|haiku|flash|lite)\\b', model_id))
    if is_executor_pattern:
        # Executor patterns are tested first; these end up executor.
        assert Tier.EXECUTOR in a.tiers, f"{model_id}: {a}"
    else:
        assert Tier.PLANNER in a.tiers, f"{model_id}: {a}"
        assert a.primary_tier == Tier.PLANNER, f"{model_id}: primary={a.primary_tier}"


# -- Executor via name pattern ------------------------------------------------


@pytest.mark.parametrize("model_id", [
    "claude-haiku-4-5",
    "claude-haiku-9-future",        # future-proof
    "claude-3-haiku",
    "gemini-flash",
    "gemini-flash-lite",
    "gpt-4o-mini",
    "gpt-7-nano",                   # future-proof
    "amazon.nova-2-micro",
    "amazon.nova-lite",
    "deepseek-chat",
    "codestral-2024",
    "qwen-7b",
    "llama-8b",
    "phi-3-7b",
    "tinyllama-1b",
    "qwen2.5-0.5b",
])
def test_executor_patterns(model_id: str) -> None:
    a = classify_model(_info(model_id))
    assert a.tiers == frozenset({Tier.EXECUTOR}), f"{model_id}: {a}"
    assert a.primary_tier == Tier.EXECUTOR


# -- Live pricing ------------------------------------------------------------


def test_pricing_planner_floor_assigns_planner() -> None:
    a = classify_model(_info("future-3000-mystery", input_per_m=15.0))
    assert a.tiers == frozenset({Tier.PLANNER})
    assert a.reason == "price"


def test_pricing_executor_ceiling_assigns_executor() -> None:
    a = classify_model(_info("future-3000-cheap", input_per_m=0.50))
    assert a.tiers == frozenset({Tier.EXECUTOR})
    assert a.reason == "price"


def test_pricing_mid_lands_in_both() -> None:
    a = classify_model(_info("future-3000-medium", input_per_m=2.0))
    assert a.tiers == frozenset({Tier.PLANNER, Tier.EXECUTOR})
    assert a.primary_tier == Tier.EXECUTOR
    assert a.reason == "price_mid"


# -- Parameter-count signal --------------------------------------------------


def test_param_count_large_local_model_is_planner_preferred() -> None:
    # 70B local model with no name pattern -> should still get planner-pref.
    a = classify_model(_info("custom/big-thinker", parameter_count_b=70.0))
    assert a.tiers == frozenset({Tier.PLANNER, Tier.EXECUTOR})
    assert a.primary_tier == Tier.PLANNER
    assert a.reason == "param_count"


def test_param_count_small_local_model_is_executor_only() -> None:
    a = classify_model(_info("custom/small-quick", parameter_count_b=3.0))
    assert a.tiers == frozenset({Tier.EXECUTOR})
    assert a.reason == "param_count"


def test_param_count_mid_local_model_is_both_executor_pref() -> None:
    a = classify_model(_info("custom/mid", parameter_count_b=20.0))
    assert a.tiers == frozenset({Tier.PLANNER, Tier.EXECUTOR})
    assert a.primary_tier == Tier.EXECUTOR
    assert a.reason == "param_count"


# -- Override file -----------------------------------------------------------


def test_override_planner(tmp_path: Path) -> None:
    p = tmp_path / "tiers.toml"
    p.write_text("""
[overrides]
"my/secret-strong-model" = "planner"
""", encoding="utf-8")
    overrides = load_overrides(p)
    a = classify_model(_info("my/secret-strong-model"), overrides=overrides)
    assert a.tiers == frozenset({Tier.PLANNER})
    assert a.reason == "override"


def test_override_executor(tmp_path: Path) -> None:
    p = tmp_path / "tiers.toml"
    p.write_text("""
[overrides]
"some-misclassified-large-model" = "executor"
""", encoding="utf-8")
    a = classify_model(
        _info("some-misclassified-large-model"),
        overrides=load_overrides(p),
    )
    assert a.tiers == frozenset({Tier.EXECUTOR})
    assert a.reason == "override"


def test_override_both(tmp_path: Path) -> None:
    p = tmp_path / "tiers.toml"
    p.write_text("""
[overrides]
"flexible/model" = "both"
""", encoding="utf-8")
    a = classify_model(_info("flexible/model"), overrides=load_overrides(p))
    assert a.tiers == frozenset({Tier.PLANNER, Tier.EXECUTOR})
    assert a.primary_tier == Tier.EXECUTOR
    assert a.reason == "override"


def test_invalid_override_value_is_ignored(tmp_path: Path) -> None:
    p = tmp_path / "tiers.toml"
    p.write_text("""
[overrides]
"weird-model" = "skylord"
""", encoding="utf-8")
    overrides = load_overrides(p)
    assert "weird-model" not in overrides


def test_missing_override_file_returns_empty(tmp_path: Path) -> None:
    overrides = load_overrides(tmp_path / "does-not-exist.toml")
    assert overrides == {}


# -- Override priority over heuristics ---------------------------------------


def test_override_beats_name_pattern(tmp_path: Path) -> None:
    """Even though 'opus' matches planner pattern, override wins."""
    p = tmp_path / "tiers.toml"
    p.write_text("""
[overrides]
"my-opus-rebrand" = "executor"
""", encoding="utf-8")
    a = classify_model(_info("my-opus-rebrand"), overrides=load_overrides(p))
    assert a.tiers == frozenset({Tier.EXECUTOR})
    assert a.reason == "override"


def test_override_beats_pricing(tmp_path: Path) -> None:
    """Override wins even if live pricing says otherwise."""
    p = tmp_path / "tiers.toml"
    p.write_text("""
[overrides]
"cheap-but-strategic" = "planner"
""", encoding="utf-8")
    a = classify_model(
        _info("cheap-but-strategic", input_per_m=0.10),
        overrides=load_overrides(p),
    )
    assert a.tiers == frozenset({Tier.PLANNER})
    assert a.reason == "override"


# -- Unknown models default safely -------------------------------------------


def test_unknown_model_defaults_to_both_executor_preferred() -> None:
    a = classify_model(_info("totally-unknown-xyz-9999"))
    assert a.tiers == frozenset({Tier.PLANNER, Tier.EXECUTOR})
    assert a.primary_tier == Tier.EXECUTOR
    assert a.reason == "default"


# -- Real model strings observed on the user's machine ------------------------


def test_real_machine_models() -> None:
    # claude_code subscription model
    a = classify_model(_info("claude-sonnet-4-7-20251101"))
    assert a.primary_tier == Tier.PLANNER

    # bedrock Anthropic models from list
    a = classify_model(_info("anthropic.claude-haiku-4-5-20251001-v1:0"))
    assert a.primary_tier == Tier.EXECUTOR

    a = classify_model(_info("anthropic.claude-opus-4-7"))
    assert a.primary_tier == Tier.PLANNER

    a = classify_model(_info("amazon.nova-2-lite-v1:0"))
    assert a.primary_tier == Tier.EXECUTOR

    # local GGUF
    a = classify_model(_info("qwen2.5-1.5b-instruct-q4_k_m.gguf"))
    assert a.primary_tier == Tier.EXECUTOR
