from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "forge-stack.sh"


def _read_helper() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_posix_stack_helper_uses_dev_compose_file() -> None:
    text = _read_helper()

    assert 'COMPOSE_FILE="$repo_root/docker/docker-compose.dev.yml"' in text
    assert 'docker compose -f "$COMPOSE_FILE"' in text
    assert "../docker-compose.dev.yml" not in text


@pytest.mark.parametrize(
    "command",
    [
        "up",
        "down",
        "reset",
        "status",
        "logs",
        "psql",
        "redis",
        "pull-ollama-model",
    ],
)
def test_posix_stack_helper_exposes_powershell_command_parity(command: str) -> None:
    assert f"{command})" in _read_helper()


def test_posix_stack_helper_uses_matching_stack_commands() -> None:
    text = _read_helper()

    expected_snippets = [
        "compose --profile llm up -d",
        "compose up -d",
        "compose ps",
        "compose down",
        'compose logs -f --tail=100 "$service"',
        "docker exec -it forge-postgres psql -U forge -d forge",
        "docker exec -it forge-soak-redis redis-cli",
        'docker exec forge-ollama ollama pull "$ollama_model"',
    ]

    for snippet in expected_snippets:
        assert snippet in text


def test_posix_stack_helper_requires_yes_before_volume_reset() -> None:
    text = _read_helper()

    assert "Type 'yes' to confirm" in text
    assert '[[ "$confirm" != "yes" ]]' in text
    assert "compose down -v --remove-orphans" in text


def test_posix_stack_helper_has_valid_bash_syntax() -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available on this host")

    result = subprocess.run(
        [bash, "-n", "-s"],
        capture_output=True,
        check=False,
        input=_read_helper().encode("utf-8"),
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
