"""
tests/properties/test_property_28_no_env_autoload.py
Property 28: No .env auto-loading
Validates Requirements 8.6.

The platform configuration loader (PlatformSettings) must read configuration
exclusively from os.environ.  It must never invoke any .env file loading
mechanism (e.g., dotenv.load_dotenv).  This is an OPSEC-critical guarantee:
operators rely on the absence of automatic .env loading so that credentials
left on disk during one engagement cannot leak into another.

This property test asserts three invariants:

  1. Static invariant - PlatformSettings.model_config disables .env file
     sources unconditionally (env_file is None).

  2. Dynamic invariant - given any plausible .env file contents, dropping
     such a file into the current working directory does not influence the
     resolved settings.  Values come exclusively from os.environ.

  3. Module hygiene - forge.config does not import or reference
     dotenv / load_dotenv at the module level.
"""

from __future__ import annotations

import os
import re
import string
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from forge.config import PlatformSettings


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------
#
# A .env line is conventionally ``KEY=VALUE``.  We restrict KEY to the
# characters that POSIX shells and dotenv parsers accept (uppercase letters,
# digits, underscore, leading non-digit) so the file is well-formed and any
# autoloading parser would actually pick the entry up.  VALUE is arbitrary
# printable text excluding NUL, CR, and LF so the file remains a valid
# .env document.

_KEY_FIRST_CHAR = st.sampled_from(string.ascii_uppercase + "_")
_KEY_TAIL_CHAR = st.sampled_from(string.ascii_uppercase + string.digits + "_")

# Settings field names that, if loaded from .env, would visibly mutate the
# resolved PlatformSettings instance.  We deliberately bias toward these so
# the property has high power against any accidental dotenv loader.
_PLATFORM_FIELD_NAMES: tuple[str, ...] = (
    "REDIS_URL",
    "STATE_DB_URL",
    "PLUGIN_DIR",
    "LLM_PROVIDER",
    "LLM_MODEL_PATH",
    "PROVIDER_TIMEOUT",
    "HEARTBEAT_INTERVAL",
    "SAFE_MODE",
    "SCOPE_JSON",
    "GOVERNANCE_RULES",
    "AUDIT_DB_URL",
    "TELEMETRY_THRESHOLD_MS",
    "MESSAGE_RETRY_MAX",
    "MESSAGE_ACK_TIMEOUT",
)


@st.composite
def _env_key(draw: st.DrawFn) -> str:
    """Generate a syntactically valid .env key.

    Half the keys target the FORGE_<PLATFORM_FIELD> namespace so the property
    is sensitive to dotenv leakage that would actually corrupt settings.
    The other half exercise arbitrary keys to ensure no key shape causes the
    loader to behave differently.
    """
    use_platform_field = draw(st.booleans())
    if use_platform_field:
        field = draw(st.sampled_from(_PLATFORM_FIELD_NAMES))
        return f"FORGE_{field}"

    head = draw(_KEY_FIRST_CHAR)
    tail = draw(st.text(alphabet=_KEY_TAIL_CHAR, min_size=0, max_size=24))
    return head + tail


# Printable values without quoting peculiarities or line terminators.
_VALUE_ALPHABET = "".join(
    ch for ch in string.printable if ch not in "\r\n\x0b\x0c"
)
_env_value = st.text(alphabet=_VALUE_ALPHABET, min_size=0, max_size=64)


@st.composite
def _env_file_lines(draw: st.DrawFn) -> list[tuple[str, str]]:
    """Generate a small list of (key, value) pairs to write into a .env file."""
    pairs = draw(
        st.lists(
            st.tuples(_env_key(), _env_value),
            min_size=1,
            max_size=8,
            unique_by=lambda kv: kv[0],
        )
    )
    return pairs


def _serialize_env_file(pairs: list[tuple[str, str]]) -> str:
    """Serialize key/value pairs into .env on-disk format.

    Values are wrapped in double quotes when they contain spaces, ``=``, or
    ``#`` so any compliant dotenv parser would accept them verbatim.
    """
    lines: list[str] = []
    for key, value in pairs:
        if any(ch in value for ch in (' ', '\t', '=', '#', '"', "'")):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{key}="{escaped}"')
        else:
            lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snapshot(settings_obj: PlatformSettings) -> dict[str, object]:
    """Capture all settings field values as a comparable dict."""
    return settings_obj.model_dump()


def _clear_forge_env() -> dict[str, str]:
    """Remove all FORGE_-prefixed env vars so settings come from defaults.

    Returns the original mapping for restoration.
    """
    saved: dict[str, str] = {}
    for key in list(os.environ):
        if key.startswith("FORGE_"):
            saved[key] = os.environ.pop(key)
    return saved


def _restore_env(saved: dict[str, str]) -> None:
    """Re-instate previously saved FORGE_ environment variables."""
    for key in list(os.environ):
        if key.startswith("FORGE_"):
            del os.environ[key]
    os.environ.update(saved)


# ---------------------------------------------------------------------------
# Static invariants (fast, no hypothesis required)
# ---------------------------------------------------------------------------


class TestModelConfigDisablesEnvFile:
    """The PlatformSettings model_config explicitly disables .env loading."""

    def test_env_file_is_none(self) -> None:
        """model_config['env_file'] must be None to suppress .env autoload."""
        assert PlatformSettings.model_config.get("env_file") is None

    def test_module_does_not_call_load_dotenv(self) -> None:
        """forge.config source must not invoke dotenv.load_dotenv at import."""
        config_path = Path(__file__).resolve().parents[2] / "forge" / "config.py"
        source = config_path.read_text(encoding="utf-8")
        # Strip docstrings and comments would be ideal but a regex on raw
        # tokens is sufficient: any literal call to load_dotenv() is a bug.
        assert not re.search(r"\bload_dotenv\s*\(", source), (
            "forge/config.py must not call load_dotenv(); .env auto-loading "
            "is forbidden by Requirement 8.6."
        )

    def test_module_does_not_import_dotenv(self) -> None:
        """forge.config must not import the dotenv package."""
        config_path = Path(__file__).resolve().parents[2] / "forge" / "config.py"
        source = config_path.read_text(encoding="utf-8")
        assert not re.search(r"^\s*import\s+dotenv\b", source, re.MULTILINE)
        assert not re.search(r"^\s*from\s+dotenv\b", source, re.MULTILINE)


# ---------------------------------------------------------------------------
# Property 28
# ---------------------------------------------------------------------------


@given(pairs=_env_file_lines())
@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)
def test_property_28_dotenv_file_in_cwd_is_ignored(
    pairs: list[tuple[str, str]],
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Dropping any plausible .env into CWD must not affect PlatformSettings.

    The settings instance constructed with a .env file present in the working
    directory must equal the settings instance constructed in a clean
    directory with no .env file.  Equality of every model field is the
    semantic test for "the file was ignored".
    """
    # Working directory containing a hypothetical .env file.
    work_dir: Path = tmp_path_factory.mktemp("env_autoload_probe")
    env_file = work_dir / ".env"
    env_file.write_text(_serialize_env_file(pairs), encoding="utf-8")

    # Avoid contamination from FORGE_ env vars already exported in the test
    # process: the property is about file-vs-environ precedence.
    saved = _clear_forge_env()
    original_cwd = Path.cwd()
    try:
        # Baseline: defaults only, no .env reachable.
        baseline = _snapshot(PlatformSettings())

        # Probe: same env vars, but a .env file is now in CWD.
        os.chdir(work_dir)
        with_dotenv = _snapshot(PlatformSettings())
    finally:
        os.chdir(original_cwd)
        _restore_env(saved)

    assert with_dotenv == baseline, (
        "PlatformSettings was influenced by a .env file in CWD. "
        f"Settings differ on fields: "
        f"{[k for k in baseline if baseline[k] != with_dotenv.get(k)]}"
    )


@given(
    pairs=_env_file_lines(),
    explicit_provider=st.sampled_from(["llama_cpp", "ollama", "vllm"]),
)
@settings(
    max_examples=50,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)
def test_property_28_environ_takes_precedence_over_dotenv(
    pairs: list[tuple[str, str]],
    explicit_provider: str,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Settings come exclusively from os.environ, even with a competing .env file.

    Construct a .env that *would* set FORGE_LLM_PROVIDER to a sentinel value
    and simultaneously export FORGE_LLM_PROVIDER in the environment.  The
    resolved value must always match os.environ, never the .env file.
    """
    sentinel = "dotenv_sentinel_should_never_load"
    # Force a conflicting entry into the .env contents.
    pairs_with_conflict = [
        ("FORGE_LLM_PROVIDER", sentinel),
        *[(k, v) for k, v in pairs if k != "FORGE_LLM_PROVIDER"],
    ]

    work_dir: Path = tmp_path_factory.mktemp("env_autoload_precedence")
    (work_dir / ".env").write_text(
        _serialize_env_file(pairs_with_conflict), encoding="utf-8"
    )

    # Skip degenerate inputs where the explicit env-var equals the sentinel,
    # which would make the precedence assertion vacuous.
    assume(explicit_provider != sentinel)

    saved = _clear_forge_env()
    original_cwd = Path.cwd()
    try:
        os.environ["FORGE_LLM_PROVIDER"] = explicit_provider
        os.chdir(work_dir)

        resolved = PlatformSettings()
    finally:
        os.chdir(original_cwd)
        _restore_env(saved)

    assert resolved.llm_provider == explicit_provider, (
        f"PlatformSettings.llm_provider resolved to {resolved.llm_provider!r}; "
        f"expected {explicit_provider!r} from os.environ. "
        "A value from the .env file would indicate auto-loading."
    )
    assert resolved.llm_provider != sentinel


@given(pairs=_env_file_lines())
@settings(
    max_examples=50,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)
def test_property_28_alternate_dotenv_filenames_are_ignored(
    pairs: list[tuple[str, str]],
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Common dotenv filename variants in CWD must also be ignored.

    Some dotenv libraries auto-discover ``.env.local``, ``.env.development``,
    or files referenced via the ``DOTENV_PATH`` env var.  None of these
    should influence PlatformSettings.
    """
    work_dir: Path = tmp_path_factory.mktemp("env_autoload_variants")
    serialized = _serialize_env_file(pairs)
    for name in (".env", ".env.local", ".env.development", ".env.test"):
        (work_dir / name).write_text(serialized, encoding="utf-8")
    side_file = work_dir / "alt.env"
    side_file.write_text(serialized, encoding="utf-8")

    saved = _clear_forge_env()
    original_cwd = Path.cwd()
    saved_dotenv_path = os.environ.pop("DOTENV_PATH", None)
    try:
        # A misbehaving loader might honour DOTENV_PATH.
        os.environ["DOTENV_PATH"] = str(side_file)

        baseline = _snapshot(PlatformSettings())

        os.chdir(work_dir)
        with_files = _snapshot(PlatformSettings())
    finally:
        os.chdir(original_cwd)
        os.environ.pop("DOTENV_PATH", None)
        if saved_dotenv_path is not None:
            os.environ["DOTENV_PATH"] = saved_dotenv_path
        _restore_env(saved)

    assert with_files == baseline, (
        "PlatformSettings was influenced by a dotenv file variant. "
        f"Settings differ on fields: "
        f"{[k for k in baseline if baseline[k] != with_files.get(k)]}"
    )
