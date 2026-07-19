"""
forge/phase4/version_parser.py
Service Banner Version Parser — Module 4-A support.

Responsibility:
  Parse service banners, HTTP Server headers, and arbitrary version strings into
  normalised (product, major, minor, patch, prerelease) tuples suitable for
  fuzzy matching against the exploit cache.

Design principles:
  - Pure functions; no I/O, no DB access.
  - All regex compiled at module load time.
  - Returns None on parse failure; never raises on malformed input.
  - CPE 2.3 URI output for NVD CVSS lookup alignment.

Supported banner formats:
  - Semantic version:   1.2.3, 1.2.3-beta, 1.2.3+build42
  - Windows build:      10.0.19041, 6.3.9600
  - Apache-style:       Apache/2.4.51 (Ubuntu)
  - OpenSSH:            OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  - IIS:                Microsoft-IIS/10.0
  - nginx:              nginx/1.24.0
  - MySQL/MariaDB:      5.7.39-log, 10.6.12-MariaDB
  - SMB:                SMB 3.1.1, dialect 0x0311
  - Generic X/Y.Z.W:   product/X.Y.Z
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ── Version token ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ParsedVersion:
    product:    str
    major:      int
    minor:      int
    patch:      int
    prerelease: Optional[str] = None
    raw:        str           = ""

    def as_tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def cpe_product(self) -> str:
        """Return a lowercase, underscore-normalised product name for CPE matching."""
        return re.sub(r"[^a-z0-9]+", "_", self.product.lower()).strip("_")

    def cpe_version(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{self.prerelease}" if self.prerelease else base

    def cpe_uri(self) -> str:
        return f"cpe:2.3:a:*:{self.cpe_product()}:{self.cpe_version()}:*:*:*:*:*:*:*"

    def __str__(self) -> str:
        return f"{self.product} {self.cpe_version()}"


# ── Compiled patterns ──────────────────────────────────────────────────────────

# Generic  product/X.Y.Z  or  product X.Y.Z
_SLASH_VER  = re.compile(
    r"(?P<product>[A-Za-z][A-Za-z0-9_\-\.]+)"
    r"[/ ]"
    r"(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?"
    r"(?:-(?P<pre>[A-Za-z0-9_.\-]+))?",
    re.IGNORECASE,
)

# Bare semver:  1.2.3, 1.2.3-beta, 1.2.3+build
_SEMVER = re.compile(
    r"\b(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?:-(?P<pre>[A-Za-z0-9_.\-]+))?(?:\+[A-Za-z0-9_.\-]+)?\b"
)

# OpenSSH  OpenSSH_8.9p1
_OPENSSH = re.compile(
    r"OpenSSH[_/ ](?P<major>\d+)\.(?P<minor>\d+)(?:p(?P<patch>\d+))?",
    re.IGNORECASE,
)

# SMB dialect  SMB 3.1.1
_SMB = re.compile(
    r"SMB\s+(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?",
    re.IGNORECASE,
)

# MariaDB  10.6.12-MariaDB
_MARIADB = re.compile(
    r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)-MariaDB",
    re.IGNORECASE,
)

# MySQL  5.7.39-log
_MYSQL = re.compile(
    r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)-(?:log|community|enterprise)",
    re.IGNORECASE,
)


# ── Parser ─────────────────────────────────────────────────────────────────────

class VersionParser:
    """
    Stateless banner → ParsedVersion converter.

    Usage:
        vp = VersionParser()
        pv = vp.parse("Apache/2.4.51 (Ubuntu)")
        # pv.product == "Apache", pv.major == 2, pv.minor == 4, pv.patch == 51
    """

    def parse(self, banner: str) -> Optional[ParsedVersion]:
        """
        Attempt to extract a version from an arbitrary banner string.
        Returns None if no version can be extracted.
        """
        if not banner or not isinstance(banner, str):
            return None

        banner = banner.strip()

        for extractor in (
            self._try_openssh,
            self._try_smb,
            self._try_mariadb,
            self._try_mysql,
            self._try_slash_product,
            self._try_semver,
        ):
            result = extractor(banner)
            if result:
                return result

        return None

    # ── Per-format extractors ──────────────────────────────────────────────────

    def _try_openssh(self, banner: str) -> Optional[ParsedVersion]:
        m = _OPENSSH.search(banner)
        if not m:
            return None
        return ParsedVersion(
            product    = "openssh",
            major      = int(m.group("major")),
            minor      = int(m.group("minor")),
            patch      = int(m.group("patch") or 0),
            raw        = banner,
        )

    def _try_smb(self, banner: str) -> Optional[ParsedVersion]:
        m = _SMB.search(banner)
        if not m:
            return None
        return ParsedVersion(
            product = "smb",
            major   = int(m.group("major")),
            minor   = int(m.group("minor")),
            patch   = int(m.group("patch") or 0),
            raw     = banner,
        )

    def _try_mariadb(self, banner: str) -> Optional[ParsedVersion]:
        m = _MARIADB.search(banner)
        if not m:
            return None
        return ParsedVersion(
            product = "mariadb",
            major   = int(m.group("major")),
            minor   = int(m.group("minor")),
            patch   = int(m.group("patch")),
            raw     = banner,
        )

    def _try_mysql(self, banner: str) -> Optional[ParsedVersion]:
        m = _MYSQL.search(banner)
        if not m:
            return None
        return ParsedVersion(
            product = "mysql",
            major   = int(m.group("major")),
            minor   = int(m.group("minor")),
            patch   = int(m.group("patch")),
            raw     = banner,
        )

    def _try_slash_product(self, banner: str) -> Optional[ParsedVersion]:
        m = _SLASH_VER.search(banner)
        if not m:
            return None
        return ParsedVersion(
            product    = m.group("product"),
            major      = int(m.group("major")),
            minor      = int(m.group("minor")),
            patch      = int(m.group("patch") or 0),
            prerelease = m.group("pre"),
            raw        = banner,
        )

    def _try_semver(self, banner: str) -> Optional[ParsedVersion]:
        m = _SEMVER.search(banner)
        if not m:
            return None
        # Attempt to back-derive product from text before the version
        prefix = banner[: m.start()].strip().rstrip("/- ")
        product = re.sub(r"\s+", "_", prefix.split()[-1]) if prefix else "unknown"
        return ParsedVersion(
            product    = product,
            major      = int(m.group("major")),
            minor      = int(m.group("minor")),
            patch      = int(m.group("patch")),
            prerelease = m.group("pre"),
            raw        = banner,
        )

    # ── Range matching ─────────────────────────────────────────────────────────

    @staticmethod
    def in_range(
        pv:       ParsedVersion,
        min_ver:  Optional[str] = None,
        max_ver:  Optional[str] = None,
    ) -> bool:
        """
        Return True if pv falls within [min_ver, max_ver] (inclusive).
        Accepts dotted version strings (e.g. "2.4.0").
        Either bound may be None (open-ended).
        """
        def _t(s: str) -> tuple[int, ...]:
            parts = s.split(".")
            return tuple(int(p) for p in parts if p.isdigit())

        tv = pv.as_tuple()
        if min_ver and tv < _t(min_ver):
            return False
        if max_ver and tv > _t(max_ver):
            return False
        return True

    @staticmethod
    def compare(a: ParsedVersion, b: ParsedVersion) -> int:
        """Return -1, 0, or 1 comparing a to b by (major, minor, patch)."""
        ta, tb = a.as_tuple(), b.as_tuple()
        if ta < tb:
            return -1
        if ta > tb:
            return 1
        return 0
