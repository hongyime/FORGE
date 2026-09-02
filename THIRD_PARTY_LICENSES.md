# Third-Party Licenses

FORGE bundles the following third-party software. Each component is redistributed
under its original license; full license text is included alongside the vendored
files at the path shown below.

---

## sigma.js 2.4.0

- **Purpose**: Graph visualization renderer (WebGL/Canvas) for large graphs.
- **Homepage**: <https://www.sigmajs.org>
- **Source**: <https://github.com/jacomyal/sigma.js/tree/v2.4.0>
- **npm**: <https://registry.npmjs.org/sigma/2.4.0>
- **Vendored path**: `forge/webui/static/sigma/`
- **License**: MIT
- **License file**: `forge/webui/static/sigma/LICENSE.txt`
- **Copyright**: © 2013-2021 Alexis Jacomy, Guillaume Plique
- **Integrity (SHA-256)**: see `forge/webui/static/sigma/SHA256SUMS.txt`
- **Upstream tarball SHA-1**: `efa213c82e8561138c9237c3a87cf15c0bbaee76`

MIT License summary: permission is granted free of charge to any person
obtaining a copy of the Software to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies, subject to the copyright
notice and permission notice being included in all copies. Full text
in the vendored `LICENSE.txt`.

---

## graphology 0.25.4

- **Purpose**: Robust JavaScript graph data structure; direct dependency of sigma.js.
- **Homepage**: <https://graphology.github.io/>
- **Source**: <https://github.com/graphology/graphology>
- **npm**: <https://registry.npmjs.org/graphology/0.25.4>
- **Vendored path**: `forge/webui/static/graphology/`
- **License**: MIT
- **License file**: `forge/webui/static/graphology/LICENSE.txt`
- **Copyright**: © Guillaume Plique (Yomguithereal)
- **Integrity (SHA-256)**: see `forge/webui/static/graphology/SHA256SUMS.txt`

MIT License — see the vendored `LICENSE.txt` for the full text.

---

## Verification

To re-verify integrity of vendored files against upstream:

```powershell
# From repo root
Get-Content forge/webui/static/sigma/SHA256SUMS.txt
Get-Content forge/webui/static/graphology/SHA256SUMS.txt

# Recompute and compare
Get-FileHash -Algorithm SHA256 forge/webui/static/sigma/sigma.min.js
Get-FileHash -Algorithm SHA256 forge/webui/static/graphology/graphology.umd.min.js.map
```

The Python test suite at `forge/webui/static/tests/test_vendored_libraries.py`
also verifies file presence, hash match, and source-map validity on every CI run.
