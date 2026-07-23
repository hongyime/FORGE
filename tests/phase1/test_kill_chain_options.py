from __future__ import annotations

import pytest

from forge.utils.kill_chain_options import (
    normalize_kill_chain_synthesis_depth,
    normalize_kill_chain_validation_batch_limit,
)


def test_kill_chain_synthesis_depth_budget_is_bounded() -> None:
    assert normalize_kill_chain_synthesis_depth(None) == 3
    assert normalize_kill_chain_synthesis_depth("") == 3
    assert normalize_kill_chain_synthesis_depth("5") == 5

    for value in ("0", "6", "not-int"):
        with pytest.raises(ValueError):
            normalize_kill_chain_synthesis_depth(value)


def test_kill_chain_validation_batch_budget_is_bounded() -> None:
    assert normalize_kill_chain_validation_batch_limit(None) == 16
    assert normalize_kill_chain_validation_batch_limit("") == 16
    assert normalize_kill_chain_validation_batch_limit("64") == 64

    for value in ("0", "65", "not-int"):
        with pytest.raises(ValueError):
            normalize_kill_chain_validation_batch_limit(value)
