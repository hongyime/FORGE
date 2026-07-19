"""
scripts/fetch_breaches.py
Phase 0 pre-engagement utility.

Downloads publicly available breach databases from databases.today
(WhatBreach backend) into FORGE's data/breaches/ directory.

This script is intentionally simple: it resolves the remote index,
filters entries by operator-supplied keywords, downloads matched
archives, and validates each download against its published SHA-256
checksum. No parsing or importing is performed here — run
build_basequery_cache.py or import_pwndb_dump.py afterward.

OPSEC constraints:
  - NEVER execute from infrastructure attributable to the engagement target.
  - Run only during pre-engagement sync windows from VPN or dedicated OSINT infra.
  - Downloads are validated against SHA-256 checksums; incomplete / corrupted
    files are deleted automatically — no partial files are retained.
  - All downloaded paths are registered with the engagement cleanup manifest so
    breach archives are removed at conclusion.

Usage:
    python scripts/fetch_breaches.py \\
        --keywords corporate,employee,staff \\
        --output-dir data/breaches/ \\
        --limit 10 \\
        --proxy socks5://127.0.0.1:9050

    python scripts/fetch_breaches.py \\
        --keywords acmecorp \\
        --output-dir /mnt/breach/ \\
        --limit 5 \\
        --dry-run
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
_LOG = logging.getLogger("fetch_breaches")

# databases.today API used by WhatBreach backend.
_INDEX_URL = "https://databases.today/api/search"
_CHUNK_SZ  = 65_536          # 64 KB streaming chunks
_UA        = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SZ), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Index fetch
# ---------------------------------------------------------------------------

def fetch_index(keywords: list[str], client) -> list[dict]:
    """
    Query databases.today for breach entries matching any keyword.
    Returns deduplicated list of result dicts keyed by download_url.
    """
    seen:    set[str]   = set()
    results: list[dict] = []

    for kw in keywords:
        try:
            resp = client.get(
                _INDEX_URL,
                params={"q": kw},
                headers={"User-Agent": _UA},
                timeout=30,
            )
        except Exception as exc:
            _LOG.warning("Index query failed for keyword '%s': %s", kw, exc)
            continue

        if resp.status_code != 200:
            _LOG.warning("Index query returned HTTP %d for keyword '%s'", resp.status_code, kw)
            continue

        for entry in resp.json().get("results", []):
            url = entry.get("download_url", "")
            if url and url not in seen:
                seen.add(url)
                results.append(entry)

    _LOG.info("Index resolved %d unique breach entries across %d keyword(s).", len(results), len(keywords))
    return results


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def download_entry(entry: dict, output_dir: Path, client) -> Optional[Path]:
    """
    Stream-download a single breach archive into output_dir.
    Validates SHA-256 checksum if provided in the index entry.
    Deletes and returns None on checksum mismatch or download error.
    """
    url = entry.get("download_url", "")
    if not url:
        return None

    filename  = output_dir / url.split("/")[-1]
    expected  = (entry.get("sha256") or "").lower().strip()

    # Skip already-present validated files.
    if filename.exists() and expected:
        if _sha256(filename) == expected:
            _LOG.info("SKIP (cached): %s", filename.name)
            return filename
        else:
            _LOG.warning("Cached file checksum mismatch — re-downloading: %s", filename.name)
            filename.unlink()

    _LOG.info("Downloading: %s → %s", url, filename.name)
    try:
        with client.stream("GET", url, timeout=300, headers={"User-Agent": _UA}) as resp:
            resp.raise_for_status()
            with open(filename, "wb") as fh:
                for chunk in resp.iter_bytes(_CHUNK_SZ):
                    fh.write(chunk)
    except Exception as exc:
        _LOG.error("Download failed (%s): %s", url, exc)
        filename.unlink(missing_ok=True)
        return None

    # Checksum validation.
    if expected:
        actual = _sha256(filename)
        if actual != expected:
            _LOG.error(
                "Checksum mismatch for %s (expected=%s actual=%s) — deleting.",
                filename.name, expected[:16] + "…", actual[:16] + "…",
            )
            filename.unlink()
            return None
        _LOG.info("✓ Checksum OK: %s", filename.name)
    else:
        _LOG.warning("No checksum provided for %s — skipping validation.", filename.name)

    return filename


# ---------------------------------------------------------------------------
# Cleanup manifest
# ---------------------------------------------------------------------------

def _register_cleanup(paths: list[Path], cleanup_manifest: Path) -> None:
    """Append downloaded paths to the engagement cleanup manifest."""
    try:
        with open(cleanup_manifest, "a") as fh:
            for p in paths:
                fh.write(str(p.resolve()) + "\n")
        _LOG.info("Registered %d path(s) in cleanup manifest: %s", len(paths), cleanup_manifest)
    except Exception as exc:
        _LOG.warning("Failed to update cleanup manifest: %s", exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(
    keywords: list[str],
    output_dir: Path,
    limit: int,
    proxy: Optional[str],
    dry_run: bool,
    cleanup_manifest: Optional[Path],
) -> int:
    """
    Main execution function.
    Returns count of successfully downloaded files.
    """
    try:
        import httpx  # type: ignore[import]
    except ImportError:
        _LOG.error("httpx not installed: pip install httpx")
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)

    transport = httpx.HTTPTransport(proxy=proxy) if proxy else None
    downloaded: list[Path] = []

    with httpx.Client(transport=transport, follow_redirects=True) as client:
        entries = fetch_index(keywords, client)
        entries = entries[:limit]

        if not entries:
            _LOG.warning("No matching breach entries found for keywords: %s", keywords)
            return 0

        _LOG.info("Processing %d/%d entries (limit=%d).", len(entries), len(entries), limit)

        for i, entry in enumerate(entries, 1):
            name = entry.get("name", entry.get("download_url", "").split("/")[-1])
            size = entry.get("size_bytes", 0)
            _LOG.info(
                "[%d/%d] %s (%s MB)",
                i, len(entries), name,
                f"{size / 1_048_576:.1f}" if size else "?",
            )

            if dry_run:
                _LOG.info("  [DRY-RUN] would download: %s", entry.get("download_url"))
                continue

            path = download_entry(entry, output_dir, client)
            if path:
                downloaded.append(path)
                _LOG.info("  ✓ Saved: %s", path)

    if cleanup_manifest and downloaded:
        _register_cleanup(downloaded, cleanup_manifest)

    _LOG.info(
        "Done. %d/%d files downloaded successfully%s.",
        len(downloaded), len(entries),
        " (dry-run)" if dry_run else "",
    )
    return len(downloaded)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="FORGE Phase 0: Fetch public breach databases from databases.today",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python fetch_breaches.py --keywords corporate,staff --limit 10\n"
            "  python fetch_breaches.py --keywords acmecorp --dry-run\n"
            "  python fetch_breaches.py --keywords linkedin --proxy socks5://127.0.0.1:9050\n"
        ),
    )
    parser.add_argument(
        "--keywords", nargs="+", required=True,
        help="Search keywords to filter breach index (e.g. corporate employee staff)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("data/breaches"),
        help="Directory to store downloaded breach archives (default: data/breaches/)",
    )
    parser.add_argument(
        "--limit", type=int, default=10,
        help="Maximum number of archives to download (default: 10)",
    )
    parser.add_argument(
        "--proxy", type=str, default=None,
        help="Proxy URL for download requests (e.g. socks5://127.0.0.1:9050)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print matched entries without downloading",
    )
    parser.add_argument(
        "--cleanup-manifest", type=Path, default=None,
        help="Append downloaded paths to this cleanup manifest file",
    )
    args = parser.parse_args()

    count = run(
        keywords=args.keywords,
        output_dir=args.output_dir,
        limit=args.limit,
        proxy=args.proxy,
        dry_run=args.dry_run,
        cleanup_manifest=args.cleanup_manifest,
    )
    sys.exit(0 if count >= 0 else 1)


if __name__ == "__main__":
    main()
