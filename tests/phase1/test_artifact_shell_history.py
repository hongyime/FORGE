from __future__ import annotations

import pytest

from forge.utils.artifact_shell_history import (
    SHELL_HISTORY_NAMES,
    shell_history_artifact_label,
)


@pytest.mark.parametrize("name", sorted(SHELL_HISTORY_NAMES))
def test_shell_history_artifact_label_recognizes_known_history_names(name: str) -> None:
    assert shell_history_artifact_label(name) == "shell-history"
    assert shell_history_artifact_label(f"/tmp/cache/42-{name}") == "shell-history"


@pytest.mark.parametrize(
    "value",
    [
        "History",
        "browser/History",
        "bash_history_backup",
        "fish_history.old",
        "not_bash_history.txt",
        "powershell_transcript.txt",
        "1-",
    ],
)
def test_shell_history_artifact_label_avoids_generic_history_false_positives(
    value: str,
) -> None:
    assert shell_history_artifact_label(value) == ""
