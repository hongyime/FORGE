"""Verification tests for vendored front-end libraries (U5.1).

Ensures sigma.js 2.4.0 and graphology 0.25.4 are correctly vendored:
  * expected files exist at expected paths
  * SHA-256 hashes match the values pinned in SHA256SUMS.txt (upstream npm bytes)
  * minified bundles are non-empty JavaScript
  * source maps have valid JSON structure with a `version` field
  * an HTML host page can reference all script tags without missing files

Run with: pytest forge/webui/static/tests/test_vendored_libraries.py -v
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

STATIC_ROOT = Path(__file__).resolve().parent.parent
SIGMA_DIR = STATIC_ROOT / "sigma"
GRAPHOLOGY_DIR = STATIC_ROOT / "graphology"

SIGMA_VERSION = "2.4.0"
GRAPHOLOGY_VERSION = "0.25.4"

# Pinned SHA-256 hashes — must match upstream npm tarball bytes (verified
# byte-identical between unpkg + jsDelivr at vendor time).
EXPECTED_HASHES: dict[Path, str] = {
    SIGMA_DIR / "sigma.min.js":
        "a86b7eb3578e9028ee84d792bf20f1503f0335ce769d5ad454252dc0a5787618",
    SIGMA_DIR / "sigma.js":
        "724abdd26352f5f96bdb7095524e5e2ecb59bd895f81e3c8ddfee2c1230bb62a",
    GRAPHOLOGY_DIR / "graphology.umd.min.js":
        "641ea047e2f414dead999769d62567ce3c6f1ddc334f1e728bd5edb19d337977",
    GRAPHOLOGY_DIR / "graphology.umd.min.js.map":
        "47040a32ca60146d5bd656026b2b17829372b467666bee92084197990fc94484",
    GRAPHOLOGY_DIR / "graphology.umd.js":
        "d63beb0bfb6ba249ca1badab93387953db62fc30e52d4168eb0a5be260bd44dc",
}

REQUIRED_FILES: list[Path] = [
    SIGMA_DIR / "sigma.min.js",
    SIGMA_DIR / "sigma.js",
    SIGMA_DIR / "LICENSE.txt",
    SIGMA_DIR / "VERSION.txt",
    SIGMA_DIR / "SHA256SUMS.txt",
    GRAPHOLOGY_DIR / "graphology.umd.min.js",
    GRAPHOLOGY_DIR / "graphology.umd.min.js.map",
    GRAPHOLOGY_DIR / "graphology.umd.js",
    GRAPHOLOGY_DIR / "LICENSE.txt",
    GRAPHOLOGY_DIR / "VERSION.txt",
    GRAPHOLOGY_DIR / "SHA256SUMS.txt",
]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


@pytest.mark.parametrize("path", REQUIRED_FILES, ids=lambda p: p.name)
def test_file_exists(path: Path) -> None:
    """Every vendored artifact must exist at its expected path."""
    assert path.is_file(), f"missing vendored file: {path}"
    assert path.stat().st_size > 0, f"empty vendored file: {path}"


@pytest.mark.parametrize(
    ("path", "expected"),
    list(EXPECTED_HASHES.items()),
    ids=lambda x: x.name if isinstance(x, Path) else "hash",
)
def test_sha256_matches_upstream(path: Path, expected: str) -> None:
    """SHA-256 of local bytes must equal the pinned upstream hash."""
    actual = _sha256(path)
    assert actual == expected, (
        f"hash drift on {path.name}: expected {expected}, got {actual}. "
        "Either the file was tampered with or the upstream release moved — "
        "re-vendor and update EXPECTED_HASHES."
    )


def test_sha256sums_file_matches_computed_hashes() -> None:
    """SHA256SUMS.txt must agree with re-computed hashes for every listed file."""
    for sums_file, directory in (
        (SIGMA_DIR / "SHA256SUMS.txt", SIGMA_DIR),
        (GRAPHOLOGY_DIR / "SHA256SUMS.txt", GRAPHOLOGY_DIR),
    ):
        for raw in sums_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            assert len(parts) == 2, f"malformed sums line in {sums_file}: {line!r}"
            expected_hash, filename = parts[0].lower(), parts[1].strip()
            target = directory / filename
            assert target.is_file(), f"{sums_file} references missing file {target}"
            assert _sha256(target) == expected_hash, (
                f"{sums_file}: {filename} hash mismatch"
            )


def test_sigma_min_is_javascript() -> None:
    """sigma.min.js must be non-trivial JS that exposes the Sigma global."""
    content = (SIGMA_DIR / "sigma.min.js").read_text(encoding="utf-8")
    assert len(content) > 50_000, "sigma.min.js unexpectedly small"
    assert "Sigma" in content, "sigma.min.js missing Sigma symbol"


def test_graphology_min_is_javascript() -> None:
    """graphology.umd.min.js must be non-trivial JS exposing graphology UMD."""
    content = (GRAPHOLOGY_DIR / "graphology.umd.min.js").read_text(encoding="utf-8")
    assert len(content) > 50_000, "graphology.umd.min.js unexpectedly small"
    assert "graphology" in content.lower(), (
        "graphology.umd.min.js missing graphology identifier"
    )


def test_graphology_source_map_is_valid() -> None:
    """The graphology source map must be well-formed JSON with sourcemap fields."""
    smap_path = GRAPHOLOGY_DIR / "graphology.umd.min.js.map"
    data = json.loads(smap_path.read_text(encoding="utf-8"))
    assert data.get("version") == 3, "source map version must be 3"
    assert "mappings" in data and isinstance(data["mappings"], str)
    assert "sources" in data and isinstance(data["sources"], list) and data["sources"]


def test_graphology_min_references_source_map() -> None:
    """graphology.umd.min.js must declare a sourceMappingURL for its .map file."""
    content = (GRAPHOLOGY_DIR / "graphology.umd.min.js").read_text(encoding="utf-8")
    assert "sourceMappingURL=graphology.umd.min.js.map" in content, (
        "graphology.umd.min.js is missing its sourceMappingURL directive"
    )


def test_version_files_declare_expected_versions() -> None:
    """VERSION.txt must pin the exact vendored version string."""
    sigma_ver = (SIGMA_DIR / "VERSION.txt").read_text(encoding="utf-8")
    assert f"sigma.js {SIGMA_VERSION}" in sigma_ver, (
        f"sigma VERSION.txt does not declare {SIGMA_VERSION}"
    )
    graph_ver = (GRAPHOLOGY_DIR / "VERSION.txt").read_text(encoding="utf-8")
    assert f"graphology {GRAPHOLOGY_VERSION}" in graph_ver, (
        f"graphology VERSION.txt does not declare {GRAPHOLOGY_VERSION}"
    )


def test_licenses_present_and_mit() -> None:
    """Both packages must ship their MIT LICENSE text alongside the code."""
    for lic in (SIGMA_DIR / "LICENSE.txt", GRAPHOLOGY_DIR / "LICENSE.txt"):
        text = lic.read_text(encoding="utf-8")
        assert "MIT" in text or "Permission is hereby granted" in text, (
            f"{lic} does not look like an MIT license"
        )


def test_third_party_licenses_attribution() -> None:
    """Repo-root THIRD_PARTY_LICENSES.md must attribute both packages."""
    repo_root = STATIC_ROOT
    for _ in range(6):
        if (repo_root / "THIRD_PARTY_LICENSES.md").is_file():
            break
        repo_root = repo_root.parent
    attribution = (repo_root / "THIRD_PARTY_LICENSES.md").read_text(encoding="utf-8")
    assert f"sigma.js {SIGMA_VERSION}" in attribution
    assert f"graphology {GRAPHOLOGY_VERSION}" in attribution
    assert "MIT" in attribution


def test_html_can_reference_all_scripts(tmp_path: Path) -> None:
    """A minimal HTML page must be able to reference both bundles via relative
    paths without any file being missing on disk. This is the "HTML can load
    scripts without errors" check — we build a page and verify every <script>
    src resolves to an existing file. Full browser execution belongs to an E2E
    Playwright suite; here we prove the filesystem contract."""
    html = tmp_path / "index.html"
    # HTML lives next to a copy of the static tree via relative traversal.
    graph_min = GRAPHOLOGY_DIR / "graphology.umd.min.js"
    sigma_min = SIGMA_DIR / "sigma.min.js"
    html.write_text(
        f"""<!doctype html>
<html><head><meta charset='utf-8'><title>vendor smoke</title></head>
<body>
  <div id='graph'></div>
  <script src='{graph_min.as_posix()}'></script>
  <script src='{sigma_min.as_posix()}'></script>
</body></html>
""",
        encoding="utf-8",
    )
    # Parse out every src and assert file existence.
    import re

    srcs = re.findall(r"<script[^>]+src=['\"]([^'\"]+)['\"]", html.read_text())
    assert srcs, "no <script src=...> tags found in generated HTML"
    for src in srcs:
        assert Path(src).is_file(), f"HTML references missing script: {src}"
