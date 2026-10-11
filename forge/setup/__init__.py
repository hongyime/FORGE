"""FORGE first-run setup helpers.

``forge setup`` is the single-command bootstrap that puts the local
operator state in a known-good shape (``.env`` seeded, directories
created, scope manifest and starter feed templates in place) and runs
``forge doctor`` for a readiness report.
"""

from forge.setup.first_run import (
    SETUP_SCHEMA_VERSION,
    SetupAction,
    SetupResult,
    ensure_directories,
    ensure_env_file,
    ensure_template,
    run_first_run_setup,
)

__all__ = [
    "SETUP_SCHEMA_VERSION",
    "SetupAction",
    "SetupResult",
    "ensure_directories",
    "ensure_env_file",
    "ensure_template",
    "run_first_run_setup",
]
