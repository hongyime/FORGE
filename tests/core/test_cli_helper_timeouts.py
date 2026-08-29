from __future__ import annotations

import pytest

from forge import cli_helpers


def test_report_generate_subprocess_timeout_env_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FORGE_REPORT_GENERATE_SUBPROCESS_TIMEOUT_SECONDS", raising=False)
    assert cli_helpers._report_generate_subprocess_timeout_seconds() == 300.0

    monkeypatch.setenv("FORGE_REPORT_GENERATE_SUBPROCESS_TIMEOUT_SECONDS", "45")
    assert cli_helpers._report_generate_subprocess_timeout_seconds() == 45.0

    monkeypatch.setenv("FORGE_REPORT_GENERATE_SUBPROCESS_TIMEOUT_SECONDS", "1")
    assert cli_helpers._report_generate_subprocess_timeout_seconds() == 30.0


def test_subprocess_timeout_seconds_for_module_uses_report_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORGE_REPORT_GENERATE_SUBPROCESS_TIMEOUT_SECONDS", "45")

    assert (
        cli_helpers._subprocess_timeout_seconds_for_module(
            ["report", "generate"],
            "final report",
            default_timeout_seconds=900,
        )
        == 45.0
    )
    assert (
        cli_helpers._subprocess_timeout_seconds_for_module(
            ["graph", "build"],
            "report generate",
            default_timeout_seconds=900,
        )
        == 45.0
    )
    assert (
        cli_helpers._subprocess_timeout_seconds_for_module(
            ["graph", "build"],
            "attack-path graph family",
            default_timeout_seconds=900,
        )
        == 900.0
    )


def test_prereq_subprocess_timeout_env_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FORGE_PREREQ_SUBPROCESS_TIMEOUT_SECONDS", raising=False)
    assert cli_helpers._prereq_subprocess_timeout_seconds() == 120.0

    monkeypatch.setenv("FORGE_PREREQ_SUBPROCESS_TIMEOUT_SECONDS", "75")
    assert cli_helpers._prereq_subprocess_timeout_seconds() == 75.0

    monkeypatch.setenv("FORGE_PREREQ_SUBPROCESS_TIMEOUT_SECONDS", "1")
    assert cli_helpers._prereq_subprocess_timeout_seconds() == 30.0


def test_subprocess_timeout_seconds_for_module_uses_prereq_label_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORGE_PREREQ_SUBPROCESS_TIMEOUT_SECONDS", "75")

    assert (
        cli_helpers._subprocess_timeout_seconds_for_module(
            ["cloud", "aws"],
            "prereq: cloud aws (Module 4)",
            default_timeout_seconds=900,
        )
        == 75.0
    )
