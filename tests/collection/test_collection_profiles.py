"""Tests for forge.collection.profiles and ``forge collection profiles`` CLI.

Covers:
- All 5 built-in profiles are registered with the expected names.
- Necrobrowser-style ``{type, name, params}`` serialization.
- Phase vocabulary enforcement.
- Scope-requirement properties (ROE, scope manifest, exploitation,
  active validation, goal-directed).
- emit_command behaviour: ordering, bool/int flags, extra_flags override,
  shlex quoting, positive-engagement enforcement.
- CLI: list / show / emit commands (table + JSON outputs).
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EXPECTED_NAMES: frozenset[str] = frozenset(
    {
        "quick_scan",
        "passive_recon",
        "standard_assessment",
        "full_engagement",
        "red_team",
    }
)


def _build_app():
    """Build a minimal Typer root wrapping the collection sub-app."""
    import typer

    import forge.cli_collection  # noqa: F401 — registers sub-commands
    from forge.cli import collection_app

    root = typer.Typer(no_args_is_help=True)
    root.add_typer(collection_app, name="collection")
    return root


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def app():
    return _build_app()


# ---------------------------------------------------------------------------
# Tests — forge.collection.profiles module (data model)
# ---------------------------------------------------------------------------


def test_profile_schema_constant() -> None:
    from forge.collection.profiles import PROFILE_SCHEMA

    assert PROFILE_SCHEMA == "forge.collection.profile.v1"


def test_all_builtin_profiles_registered() -> None:
    from forge.collection.profiles import BUILTIN_PROFILES

    names = {p.name for p in BUILTIN_PROFILES}
    assert names == _EXPECTED_NAMES


def test_list_profiles_returns_five() -> None:
    from forge.collection.profiles import list_profiles

    profiles = list_profiles()
    assert len(profiles) == 5


def test_profile_names_returns_display_order() -> None:
    from forge.collection.profiles import profile_names

    names = profile_names()
    assert names == [
        "quick_scan",
        "passive_recon",
        "standard_assessment",
        "full_engagement",
        "red_team",
    ]


def test_get_profile_known_name() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("passive_recon")
    assert p is not None
    assert p.name == "passive_recon"


def test_get_profile_tolerates_hyphens_and_case() -> None:
    from forge.collection.profiles import get_profile

    assert get_profile("quick-scan") is not None
    assert get_profile("QUICK_SCAN") is not None
    assert get_profile("Red-Team") is not None


def test_get_profile_unknown_returns_none() -> None:
    from forge.collection.profiles import get_profile

    assert get_profile("nonexistent") is None
    assert get_profile("") is None


# ---------------------------------------------------------------------------
# Tests — Necrobrowser-style serialization
# ---------------------------------------------------------------------------


def test_to_dict_has_type_name_params_shape() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("passive_recon")
    assert p is not None
    d = p.to_dict()
    assert d["type"] == "forge.collection.profile.v1"
    assert d["name"] == "passive_recon"
    assert "description" in d
    assert "params" in d
    params = d["params"]
    assert set(params.keys()) == {"phases", "flags", "scope_requirements", "warnings"}
    assert isinstance(params["phases"], list)
    assert isinstance(params["flags"], dict)
    assert isinstance(params["scope_requirements"], dict)
    assert isinstance(params["warnings"], list)


def test_to_dict_scope_requirements_default_fields_present() -> None:
    """Every profile's scope_requirements must expose the full default field set."""
    from forge.collection.profiles import list_profiles

    required_keys = {
        "roe_required",
        "scope_manifest_required",
        "active_validation_allowed",
        "exploitation_allowed",
        "goal_directed_allowed",
    }
    for profile in list_profiles():
        scope = profile.to_dict()["params"]["scope_requirements"]
        assert required_keys == set(scope.keys()), profile.name


# ---------------------------------------------------------------------------
# Tests — phase vocabulary
# ---------------------------------------------------------------------------


def test_allowed_phases_includes_core_phases() -> None:
    from forge.collection.profiles import ALLOWED_PHASES

    assert "recon" in ALLOWED_PHASES
    assert "osint" in ALLOWED_PHASES
    assert "active_validation" in ALLOWED_PHASES
    assert "exploitation" in ALLOWED_PHASES
    assert "goal_directed" in ALLOWED_PHASES
    assert "reporting" in ALLOWED_PHASES


def test_profile_rejects_unknown_phase() -> None:
    from forge.collection.profiles import CollectionProfile, ProfileValidationError

    with pytest.raises(ProfileValidationError, match="unknown phases"):
        CollectionProfile(
            name="bogus",
            description="bogus",
            phases=("ransomware_deploy",),
        )


def test_profile_rejects_duplicate_phases() -> None:
    from forge.collection.profiles import CollectionProfile, ProfileValidationError

    with pytest.raises(ProfileValidationError, match="duplicate"):
        CollectionProfile(
            name="dup",
            description="dup",
            phases=("recon", "recon"),
        )


def test_profile_rejects_empty_name() -> None:
    from forge.collection.profiles import CollectionProfile, ProfileValidationError

    with pytest.raises(ProfileValidationError):
        CollectionProfile(name="", description="x", phases=("recon",))


def test_profile_rejects_empty_description() -> None:
    from forge.collection.profiles import CollectionProfile, ProfileValidationError

    with pytest.raises(ProfileValidationError):
        CollectionProfile(name="x", description="", phases=("recon",))


# ---------------------------------------------------------------------------
# Tests — scope-requirement properties per profile
# ---------------------------------------------------------------------------


def test_quick_scan_scope_requirements() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("quick_scan")
    assert p is not None
    assert p.roe_required is False
    assert p.exploitation_allowed is False
    assert p.active_validation_allowed is False
    assert p.goal_directed_allowed is False


def test_passive_recon_does_not_allow_live_or_exploit() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("passive_recon")
    assert p is not None
    assert p.roe_required is False
    assert p.exploitation_allowed is False
    assert p.active_validation_allowed is False
    assert p.goal_directed_allowed is False


def test_standard_assessment_allows_active_validation_only() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("standard_assessment")
    assert p is not None
    assert p.roe_required is True
    assert p.active_validation_allowed is True
    assert p.exploitation_allowed is False
    assert p.goal_directed_allowed is False


def test_full_engagement_allows_exploitation() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("full_engagement")
    assert p is not None
    assert p.roe_required is True
    assert p.active_validation_allowed is True
    assert p.exploitation_allowed is True
    assert p.goal_directed_allowed is False


def test_red_team_allows_everything() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("red_team")
    assert p is not None
    assert p.roe_required is True
    assert p.active_validation_allowed is True
    assert p.exploitation_allowed is True
    assert p.goal_directed_allowed is True


# ---------------------------------------------------------------------------
# Tests — phase composition per profile
# ---------------------------------------------------------------------------


def test_passive_recon_phases() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("passive_recon")
    assert p is not None
    assert "recon" in p.phases
    assert "osint" in p.phases
    assert "active_validation" not in p.phases
    assert "exploitation" not in p.phases


def test_standard_assessment_includes_active_validation() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("standard_assessment")
    assert p is not None
    assert "active_validation" in p.phases
    assert "exploitation" not in p.phases
    assert "goal_directed" not in p.phases


def test_full_engagement_includes_exploitation() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("full_engagement")
    assert p is not None
    assert "exploitation" in p.phases
    assert "goal_directed" not in p.phases


def test_red_team_includes_goal_directed() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("red_team")
    assert p is not None
    assert "goal_directed" in p.phases
    assert "exploitation" in p.phases
    assert "active_validation" in p.phases


# ---------------------------------------------------------------------------
# Tests — emit_command
# ---------------------------------------------------------------------------


def test_emit_command_contains_seed_and_engagement() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("standard_assessment")
    assert p is not None
    cmd = p.emit_command("example.com", 42)
    assert cmd.startswith("forge kill-chain")
    assert "example.com" in cmd
    assert "--engagement" in cmd
    assert "42" in cmd


def test_emit_command_passive_recon_omits_attack_mode() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("passive_recon")
    assert p is not None
    cmd = p.emit_command("target.org", 1)
    assert "--no-attack-mode" in cmd
    # Keyscan skipped
    assert "--skip-keyscan" in cmd


def test_emit_command_full_engagement_enables_attack_mode() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("full_engagement")
    assert p is not None
    cmd = p.emit_command("corp.example", 5)
    assert "--attack-mode" in cmd
    assert "--auto-run-detected" in cmd
    assert "--include-offensive" in cmd


def test_emit_command_red_team_enables_go_hard() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("red_team")
    assert p is not None
    cmd = p.emit_command("corp.example", 6)
    assert "--go-hard" in cmd


def test_emit_command_integer_flag_appended_with_value() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("standard_assessment")
    assert p is not None
    cmd = p.emit_command("target.com", 10)
    parts = cmd.split()
    idx = parts.index("--max-iter")
    assert parts[idx + 1] == "7"


def test_emit_command_extra_flags_override() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("standard_assessment")
    assert p is not None
    cmd = p.emit_command("target.com", 10, extra_flags={"max-iter": 3})
    parts = cmd.split()
    idx = parts.index("--max-iter")
    assert parts[idx + 1] == "3"


def test_emit_command_quotes_seed_with_spaces() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("passive_recon")
    assert p is not None
    cmd = p.emit_command("target corp", 1)
    # shlex.quote wraps in single quotes on POSIX; Windows shlex uses doubles.
    assert ("'target corp'" in cmd) or ('"target corp"' in cmd)


def test_emit_command_rejects_zero_engagement() -> None:
    from forge.collection.profiles import ProfileValidationError, get_profile

    p = get_profile("passive_recon")
    assert p is not None
    with pytest.raises(ProfileValidationError):
        p.emit_command("example.com", 0)


def test_emit_command_rejects_blank_seed() -> None:
    from forge.collection.profiles import ProfileValidationError, get_profile

    p = get_profile("passive_recon")
    assert p is not None
    with pytest.raises(ProfileValidationError):
        p.emit_command("   ", 1)


def test_profile_is_frozen() -> None:
    from forge.collection.profiles import get_profile

    p = get_profile("passive_recon")
    assert p is not None
    with pytest.raises((AttributeError, TypeError)):
        p.name = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Tests — CLI via CliRunner
# ---------------------------------------------------------------------------


def test_cli_command_registered(app) -> None:
    """forge collection profiles sub-app must expose list/show/emit commands."""
    import forge.cli_collection  # noqa: F401
    from forge.cli import collection_app

    assert collection_app.registered_groups, "collection_app should have sub-groups"


def test_cli_profiles_list_exits_ok(runner: CliRunner, app) -> None:
    result = runner.invoke(app, ["collection", "profiles", "list"])
    assert result.exit_code == 0, result.output


def test_cli_profiles_list_shows_all_names(runner: CliRunner, app) -> None:
    result = runner.invoke(app, ["collection", "profiles", "list"])
    assert result.exit_code == 0, result.output
    for name in sorted(_EXPECTED_NAMES):
        assert name in result.output


def test_cli_profiles_list_json(runner: CliRunner, app) -> None:
    result = runner.invoke(app, ["collection", "profiles", "list", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) == 5
    names = {item["name"] for item in data}
    assert names == _EXPECTED_NAMES
    # Necrobrowser-style envelope
    for item in data:
        assert item["type"] == "forge.collection.profile.v1"
        assert "params" in item


def test_cli_profiles_show_known(runner: CliRunner, app) -> None:
    result = runner.invoke(app, ["collection", "profiles", "show", "passive_recon"])
    assert result.exit_code == 0, result.output
    assert "passive_recon" in result.output
    assert "--no-attack-mode" in result.output


def test_cli_profiles_show_unknown_exits_error(runner: CliRunner, app) -> None:
    result = runner.invoke(app, ["collection", "profiles", "show", "no-such-profile"])
    assert result.exit_code != 0


def test_cli_profiles_show_json(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app, ["collection", "profiles", "show", "full_engagement", "--json"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["name"] == "full_engagement"
    assert data["type"] == "forge.collection.profile.v1"
    assert "exploitation" in data["params"]["phases"]
    assert data["params"]["scope_requirements"]["exploitation_allowed"] is True


def test_cli_profiles_show_tolerates_hyphens(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app, ["collection", "profiles", "show", "red-team", "--json"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["name"] == "red_team"


def test_cli_profiles_emit_exits_ok(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        [
            "collection",
            "profiles",
            "emit",
            "passive_recon",
            "--seed",
            "example.com",
            "--engagement",
            "1",
        ],
    )
    assert result.exit_code == 0, result.output


def test_cli_profiles_emit_output_contains_command(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        [
            "collection",
            "profiles",
            "emit",
            "standard_assessment",
            "--seed",
            "target.org",
            "--engagement",
            "99",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "forge kill-chain" in result.output
    assert "target.org" in result.output
    assert "99" in result.output


def test_cli_profiles_emit_json(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        [
            "collection",
            "profiles",
            "emit",
            "quick_scan",
            "--seed",
            "seed.io",
            "--engagement",
            "7",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["profile"] == "quick_scan"
    assert data["seed"] == "seed.io"
    assert data["engagement"] == 7
    assert "forge kill-chain" in data["command"]
    assert data["phases"] == ["recon", "artifact_enrichment", "reporting"]
    assert data["scope_requirements"]["roe_required"] is False


def test_cli_profiles_emit_overrides_flags(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        [
            "collection",
            "profiles",
            "emit",
            "standard_assessment",
            "--seed",
            "example.com",
            "--engagement",
            "11",
            "--max-iter",
            "3",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    parts = data["command"].split()
    idx = parts.index("--max-iter")
    assert parts[idx + 1] == "3"


def test_cli_profiles_emit_unknown_exits_error(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        [
            "collection",
            "profiles",
            "emit",
            "no-such",
            "--seed",
            "x.com",
            "--engagement",
            "1",
        ],
    )
    assert result.exit_code != 0


def test_cli_profiles_emit_zero_engagement_exits_error(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        [
            "collection",
            "profiles",
            "emit",
            "passive_recon",
            "--seed",
            "x.com",
            "--engagement",
            "0",
        ],
    )
    assert result.exit_code != 0


def test_cli_profiles_full_engagement_warns_roe(runner: CliRunner, app) -> None:
    result = runner.invoke(
        app,
        [
            "collection",
            "profiles",
            "emit",
            "full_engagement",
            "--seed",
            "corp.example",
            "--engagement",
            "100",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "--roe-id" in result.output
    assert "--scope-manifest" in result.output
