"""Run the large Phase 1 orchestrator test file in stable pytest partitions.

The one-shot ``tests/phase1/test_engagement_orchestrator.py`` invocation can run
long enough to hit agent/tool timeouts. This helper first collects concrete
pytest node IDs, then runs bounded chunks so each command has a smaller wall
clock and failures point to a precise partition.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import gettempdir
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEST_FILE = Path("tests/phase1/test_engagement_orchestrator.py")


def _project_python(root: Path = ROOT) -> Path:
    if os.name == "nt":
        candidate = root / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = root / ".venv" / "bin" / "python"
    return candidate if candidate.exists() else Path(sys.executable)


def _normalize_nodeid_prefix(test_file: Path | str) -> str:
    return str(test_file).replace("\\", "/").rstrip("/")


def parse_collected_nodeids(output: str, test_file: Path | str = DEFAULT_TEST_FILE) -> list[str]:
    """Extract pytest node IDs for the target file from collect-only output."""

    prefix = _normalize_nodeid_prefix(test_file)
    nodeids: list[str] = []
    seen: set[str] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip().replace("\\", "/")
        if not line.startswith(f"{prefix}::"):
            continue
        if line in seen:
            continue
        seen.add(line)
        nodeids.append(line)
    return nodeids


def chunked(items: Sequence[str], chunk_size: int) -> list[list[str]]:
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")
    return [list(items[index : index + chunk_size]) for index in range(0, len(items), chunk_size)]


def pytest_engagement_temp_dirs(roots: Iterable[Path] | None = None) -> list[Path]:
    """Return pytest temp dirs containing engagement DBs.

    Safety guard: only pytest run directories named ``pytest-*`` are eligible
    for removal. Pytest owner containers such as ``pytest-of-user`` are never
    removed wholesale; their direct ``pytest-*`` children are inspected instead.
    """

    root_candidates = list(roots or _temp_roots())
    targets: list[Path] = []
    seen: set[Path] = set()
    for root in root_candidates:
        try:
            resolved_root = root.resolve()
        except OSError:
            continue
        if not resolved_root.exists() or not resolved_root.is_dir():
            continue
        for child in sorted(resolved_root.iterdir(), key=lambda path: path.name):
            for candidate in _pytest_run_dir_candidates(child):
                if candidate in seen or not _has_engagement_test_db(candidate):
                    continue
                seen.add(candidate)
                targets.append(candidate)
    return targets


def _has_engagement_test_db(path: Path) -> bool:
    if any(path.rglob("engagement.db")):
        return True
    return any(
        candidate.stem.isdigit()
        for candidate in path.rglob("*.db")
        if candidate.parent.name == "engagements" and candidate.parent.parent.name == ".forge_data"
    )


def _pytest_run_dir_candidates(path: Path) -> list[Path]:
    if not path.is_dir():
        return []
    if _is_pytest_run_dir(path):
        return [path]
    if path.name.startswith("pytest-of-"):
        return [
            child
            for child in sorted(path.iterdir(), key=lambda item: item.name)
            if _is_pytest_run_dir(child)
        ]
    return []


def _is_pytest_run_dir(path: Path) -> bool:
    return path.is_dir() and path.name.startswith("pytest-") and not path.name.startswith("pytest-of-")


def cleanup_pytest_engagement_dbs(roots: Iterable[Path] | None = None) -> tuple[int, int]:
    removed = 0
    for target in pytest_engagement_temp_dirs(roots):
        shutil.rmtree(target, ignore_errors=True)
        removed += 1
    remaining = len(pytest_engagement_temp_dirs(roots))
    return removed, remaining


def _temp_roots() -> list[Path]:
    values = [os.environ.get("TEMP"), os.environ.get("TMP"), gettempdir()]
    roots: list[Path] = []
    seen: set[Path] = set()
    for value in values:
        if not value:
            continue
        path = Path(value)
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        roots.append(resolved)
    return roots


def run_command(command: Sequence[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    print("+ " + " ".join(command), flush=True)
    try:
        return subprocess.run(
            list(command),
            cwd=str(cwd),
            text=True,
            stdout=sys.stdout,
            stderr=sys.stderr,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        print(f"command timed out after {timeout}s: {exc.cmd}", file=sys.stderr, flush=True)
        return subprocess.CompletedProcess(list(command), 124)


def collect_nodeids(
    *,
    python: Path,
    test_file: Path,
    cwd: Path,
    timeout: int,
    extra_pytest_args: Sequence[str],
    show_collection: bool = False,
) -> list[str]:
    command = [
        str(python),
        "-m",
        "pytest",
        str(test_file),
        "--collect-only",
        "-q",
        "--color=no",
        *extra_pytest_args,
    ]
    proc = subprocess.run(
        command,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if show_collection and proc.stdout:
        print(proc.stdout, end="")
    if show_collection and proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    if proc.returncode != 0:
        if not show_collection:
            if proc.stdout:
                print(proc.stdout, end="")
            if proc.stderr:
                print(proc.stderr, end="", file=sys.stderr)
        raise SystemExit(proc.returncode)
    nodeids = parse_collected_nodeids(proc.stdout, test_file)
    if not nodeids:
        raise SystemExit(f"No pytest node IDs collected for {test_file}")
    return nodeids


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-file", default=str(DEFAULT_TEST_FILE))
    parser.add_argument("--chunk-size", type=int, default=25)
    parser.add_argument("--start-chunk", type=int, default=1)
    parser.add_argument("--max-chunks", type=int, default=0, help="0 means all chunks")
    parser.add_argument("--collect-timeout", type=int, default=120)
    parser.add_argument("--chunk-timeout", type=int, default=240)
    parser.add_argument("--list-only", action="store_true")
    parser.add_argument("--show-collection", action="store_true")
    parser.add_argument(
        "--pytest-arg",
        action="append",
        default=[],
        help="Extra pytest argument appended to collect and run commands. Repeat as needed.",
    )
    parser.add_argument("--no-cleanup", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.start_chunk < 1:
        raise SystemExit("--start-chunk must be >= 1")
    python = _project_python(ROOT)
    test_file = Path(args.test_file)
    nodeids = collect_nodeids(
        python=python,
        test_file=test_file,
        cwd=ROOT,
        timeout=args.collect_timeout,
        extra_pytest_args=args.pytest_arg,
        show_collection=args.show_collection,
    )
    partitions = chunked(nodeids, args.chunk_size)
    selected = partitions[args.start_chunk - 1 :]
    if args.max_chunks > 0:
        selected = selected[: args.max_chunks]

    print(
        f"collected={len(nodeids)} chunks={len(partitions)} "
        f"selected={len(selected)} chunk_size={args.chunk_size}",
        flush=True,
    )
    if args.list_only:
        for index, partition in enumerate(partitions, start=1):
            print(f"chunk {index}: {len(partition)} tests")
        return 0

    for offset, partition in enumerate(selected, start=args.start_chunk):
        print(f"== chunk {offset}/{len(partitions)}: {len(partition)} tests ==", flush=True)
        command = [
            str(python),
            "-m",
            "pytest",
            *partition,
            "-q",
            "--color=no",
            *args.pytest_arg,
        ]
        proc = run_command(command, cwd=ROOT, timeout=args.chunk_timeout)
        if not args.no_cleanup:
            removed, remaining = cleanup_pytest_engagement_dbs()
            print(
                f"cleanup: removed_pytest_engagement_dirs={removed} "
                f"remaining_pytest_engagement_dirs={remaining}",
                flush=True,
            )
        if proc.returncode != 0:
            return proc.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
