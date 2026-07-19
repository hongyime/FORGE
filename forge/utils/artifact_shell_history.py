from __future__ import annotations

import re
from pathlib import Path


SHELL_HISTORY_NAMES = {
    ".ash_history",
    ".bash_history",
    ".dbshell",
    ".fish_history",
    ".irb_history",
    ".ksh_history",
    ".mongosh_history",
    ".mongo_history",
    ".mysql_history",
    ".node_repl_history",
    ".psql_history",
    ".python_history",
    ".rediscli_history",
    ".rhistory",
    ".sh_history",
    ".sqlite_history",
    ".zsh_history",
    "bash_history",
    "consolehost_history.txt",
    "fish_history",
    "powershell_history.txt",
    "psql_history",
    "zsh_history",
}


def shell_history_artifact_label(value: str) -> str:
    name = _artifact_name(value)
    if not name:
        return ""
    if name in SHELL_HISTORY_NAMES:
        return "shell-history"
    cache_name = _cache_prefixed_name(name)
    if cache_name in SHELL_HISTORY_NAMES:
        return "shell-history"
    return ""


def _artifact_name(value: str) -> str:
    text = str(value or "").strip().replace("\\", "/").strip("/")
    if not text:
        return ""
    return Path(text).name.lower()


def _cache_prefixed_name(name: str) -> str:
    match = re.fullmatch(r"\d+-(.+)", str(name or "").strip().lower())
    return match.group(1) if match else ""
