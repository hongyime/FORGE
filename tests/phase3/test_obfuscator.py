"""FORGE v2 blocks payload obfuscation and defense-evasion output."""

from __future__ import annotations

import pytest

from forge.governance.rules import PolicyViolation
from forge.phase3.obfuscator import (
    ObfuscationCriterion,
    ObfuscationEngine,
    _split_string,
)


def test_obfuscation_criteria_remain_descriptive_flags() -> None:
    flags = {
        ObfuscationCriterion.VAR_MANGLE,
        ObfuscationCriterion.STRING_SPLIT,
        ObfuscationCriterion.ENCODING,
        ObfuscationCriterion.ENV_SUBSTITUTE,
        ObfuscationCriterion.CMD_FRAGMENT,
        ObfuscationCriterion.CHAR_INSERT,
    }
    assert len(flags) == 6
    assert ObfuscationCriterion.VAR_MANGLE in ObfuscationCriterion.MINIMAL


def test_split_string_helper_preserves_input_for_metadata_only() -> None:
    value = "System.Net.Sockets"
    pieces = _split_string(value)
    assert "".join(pieces) == value


@pytest.mark.parametrize("target", ["powershell", "bash", "python", "cmd"])
def test_obfuscator_rejects_all_output_targets(target: str) -> None:
    with pytest.raises(PolicyViolation, match="defense evasion"):
        ObfuscationEngine().obfuscate("example command", target=target)
