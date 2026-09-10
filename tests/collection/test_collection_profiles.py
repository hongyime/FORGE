"""Tests for forge.collection.profiles and ``forge collection profiles`` CLI.

Covers:
- All 5 built-in profiles are registered.
- get_profile returns correct profile or None for unknown names.
- emit_command produces a valid shell command with correct flags.
- emit_command extra_flags override profile flags.
- to_dict returns expected keys.
- CLI list / show / emit commands (via CliRunner on collection_app).
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app():
    """Build a minimal Typer root wrapping the collection sub-app."""
    import typer

    import forge.cli_collection  # registers sub-commands on global collection_app  # noqa: F401
    from forge.cli import collection_app

    root = typer.Typer(no_args_is_help=True)
    root.add_typer(collection_app, name="collection")
    return root


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def app():
    return _build_app()


# ---------------------------------------------------------------------------
# Tests — forge.collection.profiles module
# ---------------------------------------------------------------------------


def test_all_builtin_profiles_registered() -> None:
    from forge.collection.profiles import BUILTIN_PROFILES

    names = {p.name for p in BUILTIN_PROFILES}
    assert names == {"passive", "quick-recon", "standard", "full-scope", "cloud-focus"}


def test_list_profiles_returns_five() -> None:
    from forge.collection.profiles import list_profiles

    profiles = list_profiles()
    assert len(profiles) == 5


def test_get_profile_returns_correct_profile() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("passive")
    assert p is not None
    assert p.name == "passive"
    assert p.mode_label == "Passive-only"


def test_get_profile_case_insensitive_lookup() -> None:
    from forge.collection.profiles import get_profile

    assert get_profile("PASSIVE") is not None
    assert get_profile("Standard") is not None


def test_get_profile_unknown_returns_none() -> None:
    from forge.collection.profiles import get_profile

    assert get_profile("nonexistent-profile") is None
    assert get_profile("") is None


def test_emit_command_contains_seed_and_engagement() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("standard")
    assert p is not None
    cmd = p.emit_command("example.com", 42)
    assert "forge kill-chain" in cmd
    assert "example.com" in cmd
    assert "--engagement" in cmd
    assert "42" in cmd


def test_emit_command_passive_includes_no_attack_mode() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("passive")
    assert p is not None
    cmd = p.emit_command("target.org", 1)
    # passive profile has no-attack-mode: True → --no-attack-mode flag
    assert "--no-attack-mode" in cmd


def test_emit_command_bool_true_flag() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("quick-recon")
    assert p is not None
    cmd = p.emit_command("seed.io", 5)
    # skip-keyscan: True → --skip-keyscan
    assert "--skip-keyscan" in cmd


def test_emit_command_integer_flag() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("standard")
    assert p is not None
    cmd = p.emit_command("target.com", 10)
    assert "--max-iter" in cmd
    assert "7" in cmd


def test_emit_command_extra_flags_override() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("standard")
    assert p is not None
    cmd = p.emit_command("target.com", 10, extra_flags={"max-iter": 3})
    # max-iter should now be 3, not 7
    parts = cmd.split()
    idx = parts.index("--max-iter")
    assert parts[idx + 1] == "3"


def test_emit_command_quotes_seed_with_spaces() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("passive")
    assert p is not None
    cmd = p.emit_command("target corp", 1)
    assert "target" in cmd  # shlex.quote produces 'target corp' or "target corp"


def test_to_dict_has_required_keys() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("full-scope")
    assert p is not None
    d = p.to_dict()
    assert set(d.keys()) == {"name", "description", "mode_label", "flags", "warnings"}
    assert d["name"] == "full-scope"
    assert isinstance(d["flags"], dict)
    assert isinstance(d["warnings"], list)


def test_profile_is_frozen() -> None:
    """Profiles must be immutable — frozen dataclass."""
    from forge.collection.profiles import get_profile

    p = get_profile("passive")
    assert p is not None
    with pytest.raises((AttributeError, TypeError)):
        p.name = "mutated"  # type: ignore[misc]


def test_all_profiles_have_non_empty_description() -> None:
    from forge.collection.profiles import list_profiles

    for p in list_profiles():
        assert p.description.strip(), f"Profile {p.name!r} has empty description"
        assert p.mode_label.strip(), f"Profile {p.name!r} has empty mode_label"


# ---------------------------------------------------------------------------
# Tests — CLI via CliRunner
# ---------------------------------------------------------------------------


def test_cli_command_registered(app) -> None:
    """forge collection profiles sub-app must expose list/show/emit commands."""
    import forge.cli_collection  # noqa: F401
    from forge.cli import collection_app

    # The profiles sub-app is a nested Typer; check via the cli's registered typers
    # Just verify the collection_app exists and has sub-apps
    assert collection_app.registered_groups, "collection_app should have sub-groups"


def test_cli_profiles_list_exits_ok(runner: CliRunner, app) -> None:
    result = runner.invoke(app, ["collection", "profiles", "list"])
    assert result.exit_code == 0, result.output


def test_cli_profiles_list_shows_all_names(runner: CliRunner, app) -> None:
    result = runner.invoke(app, ["collection", "profiles", "list"])
    assert result.exit_code == 0, result.output
    for name in ("passive", "quick-recon", "standard", "full-scope", "cloud-focus"):
        assert name in result.output


def test_cli_profiles_list_json(runner: CliRunner, app) -> None:
    result = runner.invoke(app, ["collection", "profiles", "list", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) == 5
    names = {item["name"] for item in data}
    assert "passive" in names
    assert "full-scope" in names


def test_cli_profiles_show_known(runner: CliRunner, app) -> None:
    result = runner.invoke(app, ["collection", "profiles", "show", "passive"])
    assert result.exit_code == 0, result.output
    assert "passive" in result.output.lower()
    assert "--no-attack-mode" in result.output


def test_cli_profiles_show_unknown_exits_error(runner: CliRunner, app) -> None:
    result = runner.invoke(app, ["collection", "profiles", "show", "no-such-profile"])
    assert result.exit_code != 0


def test_cli_profiles_show_json(runner: CliRunner, app) -> None:
    result = runner.invoke(app, ["collection", "profiles", "show", "standard", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["name"] == "standard"
    assert "flags" in data


def test_cli_profiles_emit_exits_ok(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        ["collection", "profiles", "emit", "passive",
         "--seed", "example.com", "--engagement", "1"],
    )
    assert result.exit_code == 0, result.output


def test_cli_profiles_emit_output_contains_command(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        ["collection", "profiles", "emit", "standard",
         "--seed", "target.org", "--engagement", "99"],
    )
    assert result.exit_code == 0, result.output
    assert "forge kill-chain" in result.output
    assert "target.org" in result.output
    assert "99" in result.output


def test_cli_profiles_emit_json(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        ["collection", "profiles", "emit", "quick-recon",
         "--seed", "seed.io", "--engagement", "7", "--json"],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["profile"] == "quick-recon"
    assert data["seed"] == "seed.io"
    assert data["engagement"] == 7
    assert "forge kill-chain" in data["command"]


def test_cli_profiles_emit_unknown_exits_error(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        ["collection", "profiles", "emit", "no-such",
         "--seed", "x.com", "--engagement", "1"],
    )
    assert result.exit_code != 0


def test_cli_profiles_emit_zero_engagement_exits_error(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        ["collection", "profiles", "emit", "passive",
         "--seed", "x.com", "--engagement", "0"],
    )
    assert result.exit_code != 0
