"""Predicates for excluding filenames from identity-seed promotion."""

from __future__ import annotations

import re

_FILENAME_SUFFIXES = {
    ".7z", ".apk", ".css", ".csv", ".doc", ".docx", ".gif", ".html",
    ".ico", ".jpeg", ".jpg", ".js", ".json", ".map", ".pdf", ".php",
    ".png", ".svg", ".txt", ".wasm", ".webp", ".xml", ".yaml", ".yml",
    ".zip",
}


def is_filename_like_identity_seed(value: str) -> bool:
    """Return whether a token ending in a known file suffix looks like a filename."""
    text = str(value or "").strip().rstrip("./")
    if not text or any(char.isspace() for char in text):
        return False
    suffix = "." + text.rsplit(".", 1)[-1].casefold() if "." in text else ""
    return suffix in _FILENAME_SUFFIXES and bool(re.fullmatch(r"[\w.-]+", text))
