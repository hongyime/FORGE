"""One-shot migration: bare sqlite3.connect() -> direct_connect() across forge/."""

from __future__ import annotations

import re
from pathlib import Path

FORGE_ROOT = Path(__file__).resolve().parents[1] / "forge"

# Files that legitimately use bare sqlite3.connect (source-of-truth wrappers).
SKIP_FILES = {
    FORGE_ROOT / "db" / "session.py",
    FORGE_ROOT / "db" / "direct_connect.py",
}

# Matches sqlite3.connect(...) call opening.
CALL_RE = re.compile(r"\bsqlite3\.connect\s*\(")

# Matches sqlite3.connect(':memory:') and sqlite3.connect(':memory')
MEMORY_RE = re.compile(r"""sqlite3\.connect\s*\(\s*['"]\s*:memory:?\s*['"]""")


def find_import_insertion_point(text: str) -> int:
    """Return byte offset just after the last top-level import statement.

    Uses AST so multi-line ``from x import (\n  a,\n  b,\n)`` is handled
    correctly. Falls back to byte 0 if the file has no imports (unlikely
    for our use case).
    """
    import ast
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return 0

    # Find the last top-level Import / ImportFrom node.
    last_import: ast.stmt | None = None
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last_import = node
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            # Top-of-file docstring — skip.
            continue
        else:
            # First real statement — stop scanning.
            break

    if last_import is None:
        return 0

    # end_lineno is 1-based; find byte offset of the end of that line.
    end_line = getattr(last_import, "end_lineno", last_import.lineno)
    lines = text.splitlines(keepends=True)
    offset = 0
    for i, line in enumerate(lines, start=1):
        offset += len(line)
        if i == end_line:
            return offset
    return offset


def process(path: Path) -> tuple[int, int]:
    if path in SKIP_FILES:
        return 0, 0

    text = path.read_text(encoding="utf-8")

    memory_positions = {m.start() for m in MEMORY_RE.finditer(text)}
    memory_hits = len(memory_positions)

    def _replace(match: re.Match[str]) -> str:
        if match.start() in memory_positions:
            return match.group(0)
        return "direct_connect("

    new_text, count = CALL_RE.subn(_replace, text)

    if count == 0:
        return 0, memory_hits

    if "from forge.db.direct_connect import direct_connect" not in new_text:
        insertion = find_import_insertion_point(new_text)
        import_line = (
            "from forge.db.direct_connect import direct_connect  "
            "# noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect\n"
        )
        if insertion > 0:
            new_text = new_text[:insertion] + import_line + new_text[insertion:]
        else:
            new_text = import_line + new_text

    path.write_text(new_text, encoding="utf-8")
    return count, memory_hits


def main() -> None:
    total_files = 0
    total_replacements = 0
    total_memory = 0
    for pyfile in FORGE_ROOT.rglob("*.py"):
        reps, mems = process(pyfile)
        if reps > 0:
            total_files += 1
            total_replacements += reps
            print(f"  migrated {reps:2d} sites: {pyfile.relative_to(FORGE_ROOT.parent)}")
        if mems > 0:
            total_memory += mems

    print()
    print(f"Total files migrated: {total_files}")
    print(f"Total call sites replaced: {total_replacements}")
    print(f"Total :memory: sites preserved: {total_memory}")


if __name__ == "__main__":
    main()
