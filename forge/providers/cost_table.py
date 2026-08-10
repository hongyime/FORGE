"""
forge/providers/cost_table.py - Heuristic tier classification.

The whole point of this module is to NOT hardcode model strings. Models come
and go every quarter; what's stable is the family naming convention each
vendor reuses across versions:

    * Anthropic always names its top model ``opus``, mid model ``sonnet``,
      cheap model ``haiku``.
    * OpenAI prefixes reasoning models ``o`` (o1, o3, o4) and adds ``gpt-N``
      for general models, with ``-mini`` / ``-nano`` for cheap variants.
    * Google uses ``-pro`` for top, ``-flash`` for cheap, ``-flash-lite``
      for very cheap.
    * xAI uses ``grok-N`` plus ``-mini``.
    * Mistral uses ``-large`` / ``-medium`` / ``-small``.
    * Open-weight models include parameter count: ``-7b``, ``-70b``, ``-405b``.

We classify by these family names, NOT by exact model strings, so a brand-new
``claude-opus-5`` or ``gpt-7-mini`` released next year lands in the right
tier with zero code changes.

Three layers, highest priority first:

    1. **Operator override file** (``~/.config/forge/model_tiers.toml``)
       — explicit ``"model-id" = "planner|executor|both"`` mappings.
    2. **Live pricing data** — when a backend (notably OpenRouter) returns
       per-token prices in its ``/v1/models`` response, sub-$1/M input goes
       executor, $3+/M input goes planner, in-between sits in BOTH.
    3. **Heuristic regex** — name-pattern matching as the catch-all.

A model not matching any rule lands in BOTH tiers with executor-preferred
ordering, which is the safe default.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable

__all__ = [
    "Tier",
    "TierAssignment",
    "classify_model",
    "load_overrides",
    "ModelInfo",
    "PLANNER_PATTERNS",
    "EXECUTOR_PATTERNS",
]

_LOG = logging.getLogger(__name__)


class Tier(str, Enum):
    PLANNER = "planner"
    EXECUTOR = "executor"


@dataclass(frozen=True)
class ModelInfo:
    """What discovery tells the classifier about a model."""

    model_id: str
    backend_family: str
    # Optional pricing in $/M tokens. ``None`` means unknown / subscription.
    input_per_m: float | None = None
    output_per_m: float | None = None
    # Optional parameter count in billions. ``None`` for hosted SaaS where
    # the count isn't published or doesn't apply.
    parameter_count_b: float | None = None
    # Optional context window in tokens.
    context_window: int | None = None


@dataclass(frozen=True)
class TierAssignment:
    """Outcome of classifying a model."""

    model_id: str
    tiers: frozenset[Tier]
    primary_tier: Tier  # the tier where this model is preferred
    reason: str
    # One-line user-facing summary, e.g. "matches haiku → executor"
    summary: str = field(default="")


# ---------------------------------------------------------------------------
# Heuristic name patterns
# ---------------------------------------------------------------------------

# Models whose NAME signals they're high-capability. Generic enough to survive
# new releases (claude-opus-5, gpt-7, gemini-4-pro, etc.).
PLANNER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bopus\b", re.IGNORECASE),
    re.compile(r"\bsonnet\b", re.IGNORECASE),
    # Google "pro" tier - matches gemini-pro, gemini-2.5-pro, vertex/pro
    re.compile(r"-pro\b|/pro\b|\bgemini-[\d.]+-pro", re.IGNORECASE),
    # OpenAI reasoning series: o1, o3, o4, future o5+. Avoid matching
    # arbitrary words containing "o" by anchoring on digits.
    re.compile(r"\bo[1-9]\b", re.IGNORECASE),
    # GPT-5+ general-purpose models. gpt-5, gpt-6, gpt-7, gpt-5o.
    re.compile(r"\bgpt-[5-9](?:\.\d+)?\b", re.IGNORECASE),
    # GPT-4-turbo / GPT-4o (NOT gpt-4o-mini -- mini is matched first below).
    re.compile(r"\bgpt-4o\b(?!-mini)", re.IGNORECASE),
    re.compile(r"\bgpt-4-turbo\b", re.IGNORECASE),
    # Reasoning families
    re.compile(r"\br1\b|\bdeepseek-r\d", re.IGNORECASE),
    re.compile(r"reasoning", re.IGNORECASE),
    # xAI Grok 3+
    re.compile(r"\bgrok-[3-9]\b(?!-mini)", re.IGNORECASE),
    # Mistral Large
    re.compile(r"\blarge\b", re.IGNORECASE),
    # Big open models 70B+
    re.compile(r"-(?:70|72|110|120|176|180|220|400|405)b\b", re.IGNORECASE),
    # Perplexity Sonar Pro
    re.compile(r"sonar-pro", re.IGNORECASE),
]

# Models whose NAME signals they're cheap/fast/small. Higher specificity than
# PLANNER list, so we test EXECUTOR first when both might match.
EXECUTOR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bhaiku\b", re.IGNORECASE),
    re.compile(r"\bflash\b|\blite\b", re.IGNORECASE),
    re.compile(r"\bmini\b|\bnano\b|\bmicro\b", re.IGNORECASE),
    re.compile(r"\bgpt-3\.\d+\b", re.IGNORECASE),
    # Small open models (1B-13B)
    re.compile(r"-(?:0\.\d+|[1-9](?:\.\d+)?|1[0-3])b\b", re.IGNORECASE),
    # Amazon Nova family (lite/micro caught above; pro is mid-tier)
    re.compile(r"nova-(?:lite|micro)", re.IGNORECASE),
    # DeepSeek-Chat (cheap), as opposed to DeepSeek-R1 which is planner.
    re.compile(r"deepseek.*chat", re.IGNORECASE),
    # Codestral / code-specialised cheap models
    re.compile(r"codestral", re.IGNORECASE),
    # Generic hint for distilled / quantized variants
    re.compile(r"distill|q4|q8|gguf", re.IGNORECASE),
]

# Pricing thresholds in $/M tokens, applied when live pricing data is
# available. Tuned against late-2025 published rates: $0.80/M (Haiku) is
# clearly executor; $3/M (Sonnet) is clearly planner.
PRICE_EXECUTOR_CEILING = 1.0  # $/M input tokens
PRICE_PLANNER_FLOOR = 3.0  # $/M input tokens

# Parameter-count thresholds for local models (Ollama / LM Studio / vLLM).
PARAMS_EXECUTOR_CEILING_B = 13.0
PARAMS_PLANNER_FLOOR_B = 30.0


# ---------------------------------------------------------------------------
# Override file
# ---------------------------------------------------------------------------


def _default_override_path() -> Path:
    explicit = os.environ.get("FORGE_MODEL_TIERS_PATH")
    if explicit:
        return Path(explicit)
    config_root = Path(
        os.environ.get(
            "XDG_CONFIG_HOME",
            str(Path.home() / ".config"),
        )
    )
    return config_root / "forge" / "model_tiers.toml"


def load_overrides(path: Path | None = None) -> dict[str, str]:
    """Load operator-supplied tier overrides. Always returns a dict.

    The TOML file shape is::

        [overrides]
        "anthropic.claude-opus-7" = "planner"
        "my/private-model"        = "both"

    Missing file or unreadable file is a NO-OP (returns ``{}``). A warning
    is logged so operators can debug typos without crashing the platform.
    """
    target = path or _default_override_path()
    if not target.exists():
        return {}
    try:
        # Python 3.11+ ships tomllib in stdlib.
        import tomllib  # noqa: PLC0415
    except ImportError:  # pragma: no cover - 3.10 fallback
        try:
            import tomli as tomllib  # type: ignore[no-redef] # noqa: PLC0415
        except ImportError:
            _LOG.warning("forge.cost_table: tomllib/tomli unavailable; ignoring overrides.")
            return {}
    try:
        with target.open("rb") as fh:
            data = tomllib.load(fh)
    except Exception as exc:  # noqa: BLE001 - any parse error
        _LOG.warning(
            "forge.cost_table: failed to parse %s: %s; ignoring overrides.",
            target,
            exc,
        )
        return {}
    raw = data.get("overrides", {}) or {}
    if not isinstance(raw, dict):
        _LOG.warning(
            "forge.cost_table: %s 'overrides' key is not a table; ignoring.",
            target,
        )
        return {}
    valid_values = {"planner", "executor", "both"}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        v_norm = v.strip().lower()
        if v_norm not in valid_values:
            _LOG.warning(
                "forge.cost_table: override %r=%r ignored (allowed: %s)",
                k,
                v,
                sorted(valid_values),
            )
            continue
        out[k] = v_norm
    return out


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _both(primary: Tier, reason: str, summary: str, model_id: str) -> TierAssignment:
    return TierAssignment(
        model_id=model_id,
        tiers=frozenset({Tier.PLANNER, Tier.EXECUTOR}),
        primary_tier=primary,
        reason=reason,
        summary=summary,
    )


def _planner_only(reason: str, summary: str, model_id: str) -> TierAssignment:
    return TierAssignment(
        model_id=model_id,
        tiers=frozenset({Tier.PLANNER}),
        primary_tier=Tier.PLANNER,
        reason=reason,
        summary=summary,
    )


def _executor_only(reason: str, summary: str, model_id: str) -> TierAssignment:
    return TierAssignment(
        model_id=model_id,
        tiers=frozenset({Tier.EXECUTOR}),
        primary_tier=Tier.EXECUTOR,
        reason=reason,
        summary=summary,
    )


def classify_model(
    info: ModelInfo,
    *,
    overrides: dict[str, str] | None = None,
) -> TierAssignment:
    """Map a :class:`ModelInfo` to a :class:`TierAssignment`.

    Order of precedence:

        1. Operator override (highest)
        2. Live pricing data (when available)
        3. Heuristic name patterns
        4. Parameter-count signal (for local models)
        5. Default: BOTH tiers, executor-preferred

    All branches set ``primary_tier`` so the chain orderer knows where to
    PREFER this model when the assignment is ``BOTH``.
    """
    overrides = overrides if overrides is not None else load_overrides()
    mid = info.model_id

    # 1. Operator override
    if mid in overrides:
        v = overrides[mid]
        if v == "planner":
            return _planner_only(
                reason="override",
                summary=f"override → planner",
                model_id=mid,
            )
        if v == "executor":
            return _executor_only(
                reason="override",
                summary=f"override → executor",
                model_id=mid,
            )
        return _both(
            primary=Tier.EXECUTOR,
            reason="override",
            summary=f"override → both (executor preferred)",
            model_id=mid,
        )

    # 2. Live pricing data (when available and reliable)
    if info.input_per_m is not None and info.input_per_m > 0:
        if info.input_per_m >= PRICE_PLANNER_FLOOR:
            return _planner_only(
                reason="price",
                summary=f"${info.input_per_m:.2f}/M ≥ ${PRICE_PLANNER_FLOOR:.2f} → planner",
                model_id=mid,
            )
        if info.input_per_m <= PRICE_EXECUTOR_CEILING:
            return _executor_only(
                reason="price",
                summary=f"${info.input_per_m:.2f}/M ≤ ${PRICE_EXECUTOR_CEILING:.2f} → executor",
                model_id=mid,
            )
        # Mid-priced (between ceiling and floor): both tiers, executor-pref.
        return _both(
            primary=Tier.EXECUTOR,
            reason="price_mid",
            summary=(f"${info.input_per_m:.2f}/M between executor and planner thresholds → both"),
            model_id=mid,
        )

    # 3. Heuristic name patterns. Test EXECUTOR first because cheap models
    # often share family roots with planner ones (e.g. claude-3.5-haiku
    # contains "claude" but should NOT classify as planner).
    for pat in EXECUTOR_PATTERNS:
        if pat.search(mid):
            return _executor_only(
                reason="name_pattern",
                summary=f"matches {pat.pattern!r} → executor",
                model_id=mid,
            )
    for pat in PLANNER_PATTERNS:
        if pat.search(mid):
            return _planner_only(
                reason="name_pattern",
                summary=f"matches {pat.pattern!r} → planner",
                model_id=mid,
            )

    # 4. Parameter-count signal (Ollama / LM Studio / vLLM local models)
    if info.parameter_count_b is not None:
        if info.parameter_count_b >= PARAMS_PLANNER_FLOOR_B:
            return _both(
                primary=Tier.PLANNER,
                reason="param_count",
                summary=f"{info.parameter_count_b:.0f}B params → both, planner-preferred",
                model_id=mid,
            )
        if info.parameter_count_b <= PARAMS_EXECUTOR_CEILING_B:
            return _executor_only(
                reason="param_count",
                summary=f"{info.parameter_count_b:.0f}B params ≤ {PARAMS_EXECUTOR_CEILING_B:.0f}B → executor",
                model_id=mid,
            )
        return _both(
            primary=Tier.EXECUTOR,
            reason="param_count",
            summary=(f"{info.parameter_count_b:.0f}B params (mid) → both, executor-preferred"),
            model_id=mid,
        )

    # 5. Default: both tiers, executor-preferred. Safe and reversible.
    return _both(
        primary=Tier.EXECUTOR,
        reason="default",
        summary="no signal → both, executor-preferred",
        model_id=mid,
    )


def classify_many(
    models: Iterable[ModelInfo],
    *,
    overrides: dict[str, str] | None = None,
) -> list[TierAssignment]:
    overrides = overrides if overrides is not None else load_overrides()
    return [classify_model(m, overrides=overrides) for m in models]
