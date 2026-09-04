"""U5.4 (browser) — Sigma.js 1000-node render performance in an actual browser.

Complements ``test_graph_rendering.py`` (server-side payload/layout/filter
benchmarks). This module drives a real Chromium via Playwright against the
vendored ``sigma.min.js`` + ``graphology.umd.min.js`` bundle under
``forge/webui/static/`` and asserts that constructing a graphology graph with
1,000 nodes and instantiating a Sigma renderer completes under **2 seconds**
in the browser — the U5.4 client-side ceiling.

Design constraints:
    * Fully hermetic: an in-process ``http.server`` serves the vendored UMD
      bundles and a minimal test harness page. No network, no build step, no
      Vite dev server, no dependency on the React app compiling.
    * Deterministic node/edge generation (fixed seed) so the timing captures
      only host variance, not input drift.
    * Auto-skips (does not fail) when Playwright, Chromium, or the vendored
      Sigma bundle is unavailable — the accompanying Python benchmarks still
      enforce the server-side ceilings.
"""
from __future__ import annotations

import contextlib
import http.server
import socket
import socketserver
import threading
from pathlib import Path
from typing import Any

import pytest

playwright_sync = pytest.importorskip(
    "playwright.sync_api",
    reason="playwright is required for the browser-based graph render benchmark",
)

# Hard ceiling: 1,000 nodes must render in the browser under 2 s.
THRESHOLD_BROWSER_1K_NODES_SECONDS = 2.0
NODE_COUNT = 1000
EDGE_COUNT = 2000

_STATIC_ROOT = Path(__file__).resolve().parents[2] / "forge" / "webui" / "static"
_SIGMA_JS = _STATIC_ROOT / "sigma" / "sigma.min.js"
_GRAPHOLOGY_JS = _STATIC_ROOT / "graphology" / "graphology.umd.min.js"


# ---------------------------------------------------------------------------
# Test harness page — served alongside the vendored UMD bundles.
# ---------------------------------------------------------------------------

_HARNESS_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Sigma render benchmark</title>
<style>
  html, body { margin: 0; padding: 0; width: 100%; height: 100%; }
  #graph { width: 100vw; height: 100vh; }
</style>
</head>
<body>
<div id="graph"></div>
<script src="/graphology/graphology.umd.min.js"></script>
<script src="/sigma/sigma.min.js"></script>
<script>
  // Deterministic PRNG so successive runs measure only host variance.
  function mulberry32(seed) {
    return function () {
      seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
      let t = seed;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  window.__renderMs = null;
  window.__renderError = null;
  window.__nodeCount = null;

  window.__runBenchmark = function (nodeCount, edgeCount) {
    try {
      const GraphCtor =
        (window.graphology && (window.graphology.Graph || window.graphology)) ||
        null;
      const SigmaCtor = window.Sigma || null;
      if (!GraphCtor || !SigmaCtor) {
        window.__renderError = "sigma or graphology globals missing";
        return;
      }
      const rng = mulberry32(0xf07ce54);
      const t0 = performance.now();
      const graph = new GraphCtor({ multi: false, type: "directed" });
      for (let i = 0; i < nodeCount; i += 1) {
        graph.addNode("n" + i, {
          label: "node-" + i,
          x: rng() * 2 - 1,
          y: rng() * 2 - 1,
          size: 4,
          color: "#4a9eff",
        });
      }
      for (let e = 0; e < edgeCount; e += 1) {
        const s = Math.floor(rng() * nodeCount);
        let t = Math.floor(rng() * nodeCount);
        if (t === s) t = (t + 1) % nodeCount;
        const key = "e" + e + "-" + s + "-" + t;
        if (!graph.hasEdge("n" + s, "n" + t)) {
          try {
            graph.addEdgeWithKey(key, "n" + s, "n" + t, { size: 1 });
          } catch (_) {
            // duplicate edge — skip
          }
        }
      }
      const container = document.getElementById("graph");
      const sigma = new SigmaCtor(graph, container, {
        allowInvalidContainer: true,
        renderEdgeLabels: false,
      });
      sigma.refresh();
      const t1 = performance.now();
      window.__renderMs = t1 - t0;
      window.__nodeCount = graph.order;
    } catch (err) {
      window.__renderError = String((err && err.message) || err);
    }
  };
</script>
</body>
</html>
"""


class _HarnessHandler(http.server.SimpleHTTPRequestHandler):
    """Serve the vendored UMD tree plus an in-memory harness page."""

    # Silence default noisy stderr logging during test runs.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - override signature
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib API
        if self.path in ("/", "/index.html"):
            body = _HARNESS_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


@contextlib.contextmanager
def _serve_static(root: Path):
    handler = type(
        "_BoundHandler",
        (_HarnessHandler,),
        {"directory": str(root)},
    )

    class _Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)

        def finish_request(self, request, client_address) -> None:  # type: ignore[override]
            handler(request, client_address, self, directory=str(root))

    # Bind to an ephemeral port on loopback so parallel runs cannot collide.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    server = _Server(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


def test_browser_render_1000_nodes_under_2s() -> None:
    """Scenario: Sigma.js renders 1,000 nodes in Chromium under 2 s."""
    if not _SIGMA_JS.is_file() or not _GRAPHOLOGY_JS.is_file():
        pytest.skip(
            f"vendored Sigma/graphology missing under {_STATIC_ROOT!s}; "
            "run setup to populate forge/webui/static/",
        )

    from playwright.sync_api import Error as PlaywrightError, sync_playwright

    with _serve_static(_STATIC_ROOT) as base_url:
        try:
            with sync_playwright() as pw:
                try:
                    browser = pw.chromium.launch(headless=True)
                except PlaywrightError as exc:
                    pytest.skip(f"Chromium unavailable for Playwright: {exc}")
                try:
                    context = browser.new_context(viewport={"width": 1280, "height": 800})
                    page = context.new_page()
                    page.goto(base_url + "/", wait_until="load")
                    # Wait for UMD globals to attach.
                    page.wait_for_function(
                        "() => Boolean(window.Sigma && (window.graphology && (window.graphology.Graph || window.graphology)))",
                        timeout=10_000,
                    )
                    page.evaluate(
                        "([n, e]) => window.__runBenchmark(n, e)",
                        [NODE_COUNT, EDGE_COUNT],
                    )
                    error = page.evaluate("() => window.__renderError")
                    assert not error, f"in-browser render failed: {error}"
                    render_ms = page.evaluate("() => window.__renderMs")
                    node_count = page.evaluate("() => window.__nodeCount")
                finally:
                    browser.close()
        except PlaywrightError as exc:  # pragma: no cover — environment gap
            pytest.skip(f"Playwright runtime error: {exc}")

    assert node_count == NODE_COUNT, (
        f"graphology reported {node_count} nodes; expected {NODE_COUNT}"
    )
    assert isinstance(render_ms, (int, float)), (
        f"benchmark did not record a numeric render time (got {render_ms!r})"
    )
    ceiling_ms = THRESHOLD_BROWSER_1K_NODES_SECONDS * 1000.0
    assert render_ms < ceiling_ms, (
        f"browser 1k-node Sigma render took {render_ms:.1f} ms, "
        f"exceeded {ceiling_ms:.0f} ms ceiling"
    )
