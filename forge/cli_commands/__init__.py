"""FORGE CLI subcommand modules (Click-based).

Note: located at `forge/cli_commands/` instead of `forge/cli/commands/` because
`forge/cli.py` already exists as a module and cannot coexist with a `forge/cli/`
package without breaking every `forge.cli:main` import in the codebase.

Subcommands are imported lazily by callers to avoid runpy double-import
warnings when a module is executed with `python -m`.
"""
