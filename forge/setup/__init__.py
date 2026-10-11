"""FORGE first-run setup helpers.

``forge setup`` is the single-command bootstrap that puts the local
operator state in a known-good shape (``.env`` seeded, directories
created, scope manifest and starter feed templates in place), pulls
free threat intel through :mod:`forge.feeds`, and runs ``forge doctor``
for a readiness report.
"""

from forge.setup.first_run import (
    DEFAULT_OPERATOR,
    FREE_FEED_SOURCES,
    MIN_PYTHON,
    SETUP_FEED_TIMEOUT_SECONDS,
    SETUP_SCHEMA_VERSION,
    SetupAction,
    SetupResult,
    check_python_version,
    ensure_directories,
    ensure_env_file,
    ensure_template,
    run_feeds_fetch,
    run_first_run_setup,
)

__all__ = [
    "DEFAULT_OPERATOR",
    "FREE_FEED_SOURCES",
    "MIN_PYTHON",
    "SETUP_FEED_TIMEOUT_SECONDS",
    "SETUP_SCHEMA_VERSION",
    "SetupAction",
    "SetupResult",
    "check_python_version",
    "ensure_directories",
    "ensure_env_file",
    "ensure_template",
    "run_feeds_fetch",
    "run_first_run_setup",
]
