from __future__ import annotations

import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("forge.active_validation.runner", "forge.remediation.workflow"),
        ("forge.remediation.workflow", "forge.active_validation.runner"),
        ("forge.automation_self_heal", "forge.automation_cycle"),
        ("forge.automation_cycle", "forge.automation_self_heal"),
        ("forge.connectors.validation_import", "forge.connectors.strix_findings"),
        ("forge.connectors.strix_findings", "forge.connectors.validation_import"),
        ("forge.graph.attack_path_cli", "forge.cli"),
        ("forge.cli", "forge.graph.attack_path_cli"),
        ("forge.phase6.report_synthesizer", "forge.phase6.llm_validator"),
        ("forge.phase6.llm_validator", "forge.phase6.report_synthesizer"),
        ("forge.utils.kill_chain_options", "forge.utils.kill_chain_fanout"),
        ("forge.utils.kill_chain_fanout", "forge.utils.kill_chain_options"),
    ],
)
def test_circular_import_pair_loads_in_either_order(first: str, second: str) -> None:
    result = subprocess.run(
        [sys.executable, "-c", f"import {first}; import {second}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
