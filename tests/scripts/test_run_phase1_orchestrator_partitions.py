from __future__ import annotations

import subprocess
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "run_phase1_orchestrator_partitions.py"
SPEC = spec_from_file_location("run_phase1_orchestrator_partitions", MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
runner = module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def test_parse_collected_nodeids_filters_target_file_and_dedupes() -> None:
    output = """
tests/phase1/test_engagement_orchestrator.py::test_alpha
tests/phase1/test_engagement_orchestrator.py::TestGroup::test_beta
tests/phase1/test_other.py::test_skip
tests\\phase1\\test_engagement_orchestrator.py::test_alpha
3 tests collected
"""

    assert runner.parse_collected_nodeids(output) == [
        "tests/phase1/test_engagement_orchestrator.py::test_alpha",
        "tests/phase1/test_engagement_orchestrator.py::TestGroup::test_beta",
    ]


def test_chunked_rejects_invalid_size_and_preserves_order() -> None:
    assert runner.chunked(["a", "b", "c", "d", "e"], 2) == [
        ["a", "b"],
        ["c", "d"],
        ["e"],
    ]

    try:
        runner.chunked(["a"], 0)
    except ValueError as exc:
        assert "chunk_size" in str(exc)
    else:
        raise AssertionError("chunked() accepted invalid chunk size")


def test_cleanup_only_removes_pytest_temp_dirs_with_engagement_db(tmp_path: Path) -> None:
    removable = tmp_path / "pytest-removable"
    removable_nested = removable / "case" / "engagement"
    removable_nested.mkdir(parents=True)
    (removable_nested / "engagement.db").write_text("", encoding="utf-8")

    keep_no_db = tmp_path / "pytest-keep"
    keep_no_db.mkdir()
    keep_wrong_name = tmp_path / "not-pytest"
    keep_wrong_name.mkdir()
    (keep_wrong_name / "engagement.db").write_text("", encoding="utf-8")

    assert runner.pytest_engagement_temp_dirs([tmp_path]) == [removable]

    removed, remaining = runner.cleanup_pytest_engagement_dbs([tmp_path])

    assert removed == 1
    assert remaining == 0
    assert not removable.exists()
    assert keep_no_db.exists()
    assert keep_wrong_name.exists()


def test_v11_cleanup_removes_nested_pytest_run_dirs_not_pytest_of_container(tmp_path: Path) -> None:
    container = tmp_path / "pytest-of-bryan"
    removable = container / "pytest-42"
    removable_nested = removable / "case" / "engagement"
    removable_nested.mkdir(parents=True)
    (removable_nested / "engagement.db").write_text("", encoding="utf-8")
    keep_nested = container / "pytest-keep"
    keep_nested.mkdir(parents=True)

    assert runner.pytest_engagement_temp_dirs([tmp_path]) == [removable]

    removed, remaining = runner.cleanup_pytest_engagement_dbs([tmp_path])

    assert removed == 1
    assert remaining == 0
    assert container.exists()
    assert not removable.exists()
    assert keep_nested.exists()


def test_cleanup_detects_numeric_engagement_dbs_under_pytest_run_dirs(tmp_path: Path) -> None:
    container = tmp_path / "pytest-of-bryan"
    removable = container / "pytest-43"
    engagement_root = removable / "case" / ".forge_data" / "engagements"
    engagement_root.mkdir(parents=True)
    (engagement_root / "4242.db").write_text("", encoding="utf-8")

    keep_repo_like = tmp_path / "repo" / ".forge_data" / "engagements"
    keep_repo_like.mkdir(parents=True)
    (keep_repo_like / "5010.db").write_text("", encoding="utf-8")

    assert runner.pytest_engagement_temp_dirs([tmp_path]) == [removable]

    removed, remaining = runner.cleanup_pytest_engagement_dbs([tmp_path])

    assert removed == 1
    assert remaining == 0
    assert not removable.exists()
    assert keep_repo_like.exists()


def test_run_command_returns_124_on_timeout(monkeypatch, tmp_path: Path) -> None:
    def _timeout_run(*args, **kwargs):  # noqa: ANN001, ARG001
        raise subprocess.TimeoutExpired(cmd=["python", "-m", "pytest"], timeout=1)

    monkeypatch.setattr(runner.subprocess, "run", _timeout_run)

    result = runner.run_command(["python", "-m", "pytest"], cwd=tmp_path, timeout=1)

    assert result.returncode == 124
