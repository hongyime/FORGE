from __future__ import annotations

from pathlib import Path
from typing import Any


def run_safe_check(vuln_id: str, target: str, validation_method: str, db_path: Path) -> dict[str, Any]:
    raise NotImplementedError(
        "rce_hunter.run_safe_check is not implemented. "
        "Deploy an OOB callback server and implement time-based OOB validation before use."
    )


def run_weaponize(vuln_id: str, target: str, requires_approval: bool, db_path: Path) -> dict[str, Any]:
    raise NotImplementedError(
        "rce_hunter.run_weaponize is not implemented. "
        "Operator must implement exploit delivery logic with explicit approval workflow."
    )
