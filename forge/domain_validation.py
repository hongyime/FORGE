"""Shared offline validation for domain and subdomain seed values."""

from __future__ import annotations

import re

from forge.iana_tlds import DELEGATED_TLDS


_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DOMAIN_TLD_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CODE_IDENTIFIER_TLDS = frozenset(
    {
        "args",
        "argv",
        "class",
        "cls",
        "cwd",
        "def",
        "env",
        "environ",
        "kwargs",
        "none",
        "null",
        "path",
        "return",
        "self",
        "stderr",
        "stdin",
        "stdout",
        "tmp",
        "undefined",
        "var",
    }
)

# Curated common file suffixes that are not useful domain TLDs for the
# autopilot feed. This avoids treating artifact names as engagement targets
# without shipping or refreshing an external TLD dataset. `.py` is the one
# deliberate ccTLD exception: worker.py is a common source filename, and the
# feed errs toward dropping that ambiguous candidate. `.md`, `.rs`, `.sh`,
# `.ai`, and `.so` are intentionally absent so genuine Moldova, Serbia, Saint
# Helena, Anguilla, and Somalia domains remain valid. `.zip` is also omitted
# because it is a real generic TLD. This list cannot identify every filename;
# it targets common image, document, data, and source-code suffixes.
# This is intentionally broader than a DNS/TLD policy.  Feed values can be
# URLs, cloud references, or a preserved prior feed entry as well as domains;
# treating an ambiguous file-looking suffix as a target is unsafe.  Keep this
# as the single vocabulary used by both domain validation and feed filtering.
FILENAME_LIKE_SUFFIXES = frozenset(
    {
        "7z",
        "apk",
        "aab",
        "asp",
        "aspx",
        "avif",
        "bak",
        "bin",
        "bmp",
        "cjs",
        "conf",
        "config",
        "cpp",
        "crt",
        "csr",
        "css",
        "csv",
        "dat",
        "db",
        "deb",
        "dll",
        "dmg",
        "doc",
        "docx",
        "eot",
        "env",
        "exe",
        "gif",
        "gz",
        "hbs",
        "heic",
        "htm",
        "html",
        "ico",
        "ini",
        "ipa",
        "iso",
        "jar",
        "java",
        "jpeg",
        "jpg",
        "js",
        "json",
        "jsx",
        "key",
        "lock",
        "log",
        "mjs",
        "mp3",
        "mp4",
        "odt",
        "ogg",
        "otf",
        "pdf",
        "pem",
        "php",
        "png",
        "ppt",
        "pptx",
        "properties",
        "py",
        "pyc",
        "pyi",
        "rb",
        "rpm",
        "scss",
        "shtml",
        "sql",
        "svg",
        "swf",
        "tar",
        "text",
        "tgz",
        "tif",
        "tiff",
        "toml",
        "ts",
        "tsv",
        "tsx",
        "ttf",
        "txt",
        "wasm",
        "wav",
        "webm",
        "webp",
        "woff",
        "woff2",
        "xls",
        "xlsx",
        "xml",
        "yaml",
        "yml",
        # Some of these are delegated TLDs, but are overwhelmingly emitted by
        # source trees and build artifacts in discovery output.  The target
        # feed deliberately prefers rejecting that ambiguity.
        "bash",
        "c",
        "cc",
        "dylib",
        "go",
        "h",
        "hpp",
        "markdown",
        "md",
        "ps",
        "ps1",
        "rs",
        "rst",
        "sh",
        "so",
        "zsh",
    }
)

# These suffixes are file-like enough to reject from an autonomous feed, but
# are delegated TLDs and therefore remain valid when a caller explicitly
# validates a domain.  The feed filter applies the full set above; domain
# canonicalization uses this narrower set to avoid breaking real domains.
_AMBIGUOUS_FILELIKE_TLDS = frozenset(
    {"c", "cc", "go", "h", "md", "rs", "sh", "so"}
)
DOMAIN_FILENAME_LIKE_SUFFIXES = FILENAME_LIKE_SUFFIXES - _AMBIGUOUS_FILELIKE_TLDS


def canonicalize_domain(value: str) -> str:
    """Return a normalized hostname, or an empty string when it is invalid."""
    text = str(value or "").lower()
    if (
        not text
        or any(character.isspace() for character in text)
        or len(text) > 253
        or text.startswith(".")
        or text.endswith(".")
    ):
        return ""
    labels = text.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return ""
    tld = labels[-1]
    if (
        not _DOMAIN_TLD_RE.fullmatch(tld)
        or tld not in DELEGATED_TLDS
        or tld in _CODE_IDENTIFIER_TLDS
        or tld in DOMAIN_FILENAME_LIKE_SUFFIXES
    ):
        return ""
    return text
