"""Regression test locking the LLM cascade order in one place.

P2/P3 audit item #1: the ``--help`` for ``forge kill-chain`` and the
docstring on ``_ensure_provider_loaded`` had drifted apart (one advertised
an 8-link cascade, the other named only 5). This test pins every
declaration to the single source of truth,
:data:`forge.phase6.report_synthesizer._AUTO_CASCADE_DEFAULT_ORDER`.
"""

from __future__ import annotations

from forge.phase6.report_synthesizer import _AUTO_CASCADE_DEFAULT_ORDER, ReportSynthesizer


_EXPECTED_ORDER = (
    "kiro_cli",
    "claude_code",
    "openai_compatible",
    "codex_cli",
    "gemini_cli",
    "bedrock_anthropic",
    "llama_cpp",
    "template",
)


def test_cascade_default_is_the_expected_eight_stage_pipeline() -> None:
    assert _AUTO_CASCADE_DEFAULT_ORDER == _EXPECTED_ORDER, (
        "The canonical 8-stage LLM cascade order changed. If this is "
        "intentional, update both the CLI --help (`--provider` option in "
        "forge/cli.py) and the _ensure_provider_loaded docstring in "
        "forge/phase6/report_synthesizer.py to match."
    )


def test_ensure_provider_docstring_names_every_backend() -> None:
    doc = ReportSynthesizer._ensure_provider_loaded.__doc__ or ""
    missing = [name for name in _AUTO_CASCADE_DEFAULT_ORDER if name not in doc]
    assert not missing, (
        "The _ensure_provider_loaded docstring must mention every backend in "
        f"_AUTO_CASCADE_DEFAULT_ORDER. Missing: {missing}."
    )


def test_ensure_provider_docstring_lists_backends_in_canonical_order() -> None:
    doc = ReportSynthesizer._ensure_provider_loaded.__doc__ or ""
    positions: list[tuple[int, str]] = []
    for name in _AUTO_CASCADE_DEFAULT_ORDER:
        idx = doc.find(name)
        assert idx >= 0, f"backend {name!r} not present in docstring"
        positions.append((idx, name))
    canonical_positions = sorted(positions, key=lambda pair: pair[0])
    canonical_order = [pair[1] for pair in canonical_positions]
    assert canonical_order == list(_AUTO_CASCADE_DEFAULT_ORDER), (
        "Docstring lists backends out of order relative to "
        f"_AUTO_CASCADE_DEFAULT_ORDER. Got: {canonical_order}"
    )
