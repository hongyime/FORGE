"""
tests/phase4/test_networkx_extra.py

Property 3 (C1): Import success under the ``[graph]`` optional-dependencies
extra, ``ImportError`` without.

**Validates: Requirements 2.9, 2.10**

The ``forge.phase4.attack_path`` module imports :mod:`networkx` at module
scope. The ``[graph]`` extra declared in ``pyproject.toml`` pins
``networkx>=3.0,<4.0``. This contract is exercised in both directions:

* When ``networkx`` is importable (Graph_Extra installed),
  ``forge.phase4.attack_path`` imports cleanly and exposes ``AttackGraph``
  at module scope (Requirement 2.10).
* When ``networkx`` is not importable (Graph_Extra not installed), the
  same import raises ``ImportError`` at import time (Requirement 2.9).
"""

from __future__ import annotations

import importlib
import sys
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.phase4


def test_attack_path_module_imports_when_networkx_available() -> None:
    """When ``networkx`` is importable, ``forge.phase4.attack_path`` imports
    cleanly and exposes ``AttackGraph`` at module scope.

    **Validates: Requirement 2.10**
    """
    pytest.importorskip("networkx")

    # Force a fresh import so we exercise the module-scope import chain,
    # not a cached copy that may have loaded before this test started.
    sys.modules.pop("forge.phase4.attack_path", None)

    mod = importlib.import_module("forge.phase4.attack_path")

    assert hasattr(mod, "AttackGraph"), (
        "forge.phase4.attack_path must expose AttackGraph at module scope "
        "when the [graph] extra is installed (Requirement 2.10)."
    )


def test_attack_path_module_raises_importerror_when_networkx_absent() -> None:
    """When ``networkx`` is not importable, ``forge.phase4.attack_path``
    raises ``ImportError`` at import time.

    **Validates: Requirement 2.9**

    Setting ``sys.modules["networkx"] = None`` causes Python's import
    machinery to raise ``ImportError`` on ``import networkx``, which
    faithfully simulates the Graph_Extra not being installed without
    requiring us to actually uninstall the package.
    """
    # patch.dict snapshots sys.modules on entry and restores it on exit,
    # so any pops we do inside the with-block are reverted afterwards.
    with patch.dict(sys.modules, {"networkx": None}):
        # Evict any cached copy so the import machinery re-executes the
        # module body (which is where the `import networkx as nx` lives).
        sys.modules.pop("forge.phase4.attack_path", None)

        with pytest.raises(ImportError):
            importlib.import_module("forge.phase4.attack_path")

    # Belt-and-braces cleanup: if the failed import left a partial entry,
    # remove it so subsequent tests get a clean re-import.
    sys.modules.pop("forge.phase4.attack_path", None)
