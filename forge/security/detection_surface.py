"""E3.3 - Detection Surface Measurement (DEFENSIVE POSTURE).

Measures how detectable FORGE binaries look to AV/EDR:

1. ``measure_av_signatures`` - counts AV engine hits via VirusTotal (free
   public API, rate-limited to 4 req/min) or local ClamAV/YARA when a scan
   binary is on PATH. Never uploads a binary without an explicit opt-in flag.
2. ``analyze_strings`` - extracts printable strings and flags suspicious
   tokens (``password``, ``dump``, ``inject``, ...).
3. ``measure_entropy`` - Shannon entropy of the file bytes; >7.2 is treated as
   suspicious (packed/obfuscated).

Results append to a local JSONL history for trend analysis. CI never fails on
AV detections - the workflow only emits a warning artifact.

DEFENSIVE ONLY. No offensive capability, no evasion helpers.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import string
import subprocess
import time
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

# --- Public types -----------------------------------------------------------

SUSPICIOUS_STRING_PATTERNS: tuple[str, ...] = (
    "password", "passwd", "credential", "secret", "token",
    "dump", "mimikatz", "lsass", "sekurlsa",
    "inject", "shellcode", "payload", "reverse_shell", "reverse shell",
    "meterpreter", "cobaltstrike", "cobalt strike", "beacon",
    "keylog", "keylogger", "backdoor", "rootkit", "rat",
    "exploit", "bypass_amsi", "bypass amsi", "disable_defender",
    "virtualalloc", "createremotethread", "writeprocessmemory",
    "ntunmapviewofsection", "queueuserapc", "setwindowshookex",
)

_MIN_STRING_LEN = 4
_PRINTABLE = set(string.printable) - {"\n", "\r", "\t", "\x0b", "\x0c"}
_ENTROPY_SUSPICIOUS_THRESHOLD = 7.2
_VT_ENDPOINT = "https://www.virustotal.com/api/v3/files/{sha256}"
_VT_MIN_INTERVAL_SECONDS = 15.0  # 4 req/min free tier
_DEFAULT_HISTORY_PATH = Path(".forge_data") / "detection_surface_history.jsonl"


@dataclass(frozen=True)
class Detection:
    """A single AV/EDR engine that flagged the binary."""

    engine: str
    category: str
    result: str


@dataclass(frozen=True)
class AVScanResult:
    """Aggregate AV scan across engines."""

    total_engines: int
    detected_count: int
    detections: tuple[Detection, ...]
    source: str
    sha256: str
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["detections"] = [asdict(x) for x in self.detections]
        return d


@dataclass(frozen=True)
class StringAnalysis:
    """Printable-string audit of a binary."""

    total_strings: int
    suspicious_strings: tuple[str, ...]
    matched_patterns: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_strings": self.total_strings,
            "suspicious_strings": list(self.suspicious_strings),
            "matched_patterns": list(self.matched_patterns),
        }


@dataclass(frozen=True)
class EntropyResult:
    """Shannon entropy of the file bytes."""

    entropy_score: float
    is_suspicious: bool
    byte_count: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- Core helpers -----------------------------------------------------------


def _sha256(binary_path: Path) -> str:
    h = hashlib.sha256()
    with binary_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_strings(data: bytes, min_len: int = _MIN_STRING_LEN) -> list[str]:
    """Extract printable ASCII strings (mimics GNU ``strings -a``)."""
    out: list[str] = []
    buf: list[str] = []
    for byte in data:
        ch = chr(byte)
        if ch in _PRINTABLE:
            buf.append(ch)
            continue
        if len(buf) >= min_len:
            out.append("".join(buf))
        buf.clear()
    if len(buf) >= min_len:
        out.append("".join(buf))
    return out


# --- Function 2: string analysis --------------------------------------------


def analyze_strings(
    binary_path: Path,
    patterns: Sequence[str] = SUSPICIOUS_STRING_PATTERNS,
    max_bytes: int = 64 * 1024 * 1024,
) -> StringAnalysis:
    """Extract strings from *binary_path* and flag suspicious tokens."""
    binary_path = Path(binary_path)
    if not binary_path.is_file():
        raise FileNotFoundError(f"binary not found: {binary_path}")

    data = binary_path.read_bytes()[:max_bytes]
    strings_found = _extract_strings(data)
    lowered_patterns = tuple(p.lower() for p in patterns)

    suspicious: list[str] = []
    matched: set[str] = set()
    for s in strings_found:
        low = s.lower()
        hits = [pat for pat in lowered_patterns if pat in low]
        if hits:
            suspicious.append(s)
            matched.update(hits)

    return StringAnalysis(
        total_strings=len(strings_found),
        suspicious_strings=tuple(suspicious),
        matched_patterns=tuple(sorted(matched)),
    )


# --- Function 3: Shannon entropy --------------------------------------------


def measure_entropy(
    binary_path: Path,
    threshold: float = _ENTROPY_SUSPICIOUS_THRESHOLD,
) -> EntropyResult:
    """Compute Shannon entropy (bits / byte) over the whole file."""
    binary_path = Path(binary_path)
    if not binary_path.is_file():
        raise FileNotFoundError(f"binary not found: {binary_path}")

    counts: Counter[int] = Counter()
    total = 0
    with binary_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            counts.update(chunk)
            total += len(chunk)

    if total == 0:
        return EntropyResult(entropy_score=0.0, is_suspicious=False, byte_count=0)

    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)

    return EntropyResult(
        entropy_score=round(entropy, 6),
        is_suspicious=entropy >= threshold,
        byte_count=total,
    )


# --- Function 1: AV signatures ----------------------------------------------


def _parse_vt_response(sha256: str, payload: dict[str, Any]) -> AVScanResult:
    """Turn a VirusTotal v3 file report into an ``AVScanResult``."""
    attrs = payload.get("data", {}).get("attributes", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}

    detections: list[Detection] = []
    for engine, info in results.items():
        category = (info or {}).get("category", "")
        if category in {"malicious", "suspicious"}:
            detections.append(Detection(
                engine=engine,
                category=category,
                result=(info or {}).get("result", "") or "",
            ))

    total_engines = len(results) or int(
        stats.get("harmless", 0) + stats.get("malicious", 0)
        + stats.get("suspicious", 0) + stats.get("undetected", 0)
        + stats.get("timeout", 0) + stats.get("type-unsupported", 0)
    )
    detected_count = len(detections) or int(
        stats.get("malicious", 0) + stats.get("suspicious", 0)
    )

    return AVScanResult(
        total_engines=total_engines,
        detected_count=detected_count,
        detections=tuple(detections),
        source="virustotal",
        sha256=sha256,
    )


def _vt_lookup(
    sha256: str,
    api_key: str,
    *,
    timeout: float = 20.0,
    min_interval: float = _VT_MIN_INTERVAL_SECONDS,
    _sleep: Any = time.sleep,
) -> AVScanResult:
    """Hash-lookup against VirusTotal. Never uploads the binary."""
    _sleep(min_interval)
    url = _VT_ENDPOINT.format(sha256=urllib.parse.quote(sha256))
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        raw = resp.read()
    return _parse_vt_response(sha256, json.loads(raw.decode("utf-8")))


def _clamscan_lookup(binary_path: Path, sha256: str) -> AVScanResult:
    """Run local ``clamscan --no-summary`` if it is on PATH."""
    exe = shutil.which("clamscan")
    if not exe:
        return AVScanResult(
            total_engines=0, detected_count=0, detections=(),
            source="none", sha256=sha256,
            note="clamscan not on PATH and no VirusTotal key",
        )
    try:
        proc = subprocess.run(  # noqa: S603
            [exe, "--no-summary", "--infected", str(binary_path)],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return AVScanResult(
            total_engines=1, detected_count=0, detections=(),
            source="clamav", sha256=sha256, note=f"clamscan failed: {exc}",
        )

    detections: list[Detection] = []
    for line in proc.stdout.splitlines():
        # clamscan format: "<path>: <sig> FOUND"
        m = re.match(r"^(?P<path>.+):\s+(?P<sig>.+)\s+FOUND\s*$", line)
        if m:
            detections.append(Detection(
                engine="clamav", category="malicious", result=m.group("sig"),
            ))

    return AVScanResult(
        total_engines=1,
        detected_count=len(detections),
        detections=tuple(detections),
        source="clamav",
        sha256=sha256,
        note="rc=0 clean" if proc.returncode == 0 else f"rc={proc.returncode}",
    )


def measure_av_signatures(
    binary_path: Path,
    *,
    vt_api_key: str | None = None,
    prefer: str = "auto",
    vt_lookup: Any = None,
    clamscan_lookup: Any = None,
) -> AVScanResult:
    """Return an ``AVScanResult`` describing AV signatures for *binary_path*.

    Order of preference:
      1. VirusTotal hash lookup when ``vt_api_key`` (or ``FORGE_VT_API_KEY``
         env var) is provided. Only the SHA-256 is transmitted; the binary
         itself is never uploaded.
      2. Local ``clamscan`` when the binary is on PATH.
      3. Zero-result placeholder with a ``note`` explaining why.
    """
    binary_path = Path(binary_path)
    if not binary_path.is_file():
        raise FileNotFoundError(f"binary not found: {binary_path}")

    sha256 = _sha256(binary_path)
    key = vt_api_key or os.environ.get("FORGE_VT_API_KEY")
    vt_lookup = vt_lookup or _vt_lookup
    clamscan_lookup = clamscan_lookup or _clamscan_lookup

    if prefer in {"auto", "virustotal"} and key:
        try:
            return vt_lookup(sha256, key)
        except Exception as exc:  # noqa: BLE001 - network best-effort
            note = f"VirusTotal lookup failed: {exc.__class__.__name__}"
            if prefer == "virustotal":
                return AVScanResult(
                    total_engines=0, detected_count=0, detections=(),
                    source="virustotal", sha256=sha256, note=note,
                )
            fallback = clamscan_lookup(binary_path, sha256)
            return AVScanResult(
                total_engines=fallback.total_engines,
                detected_count=fallback.detected_count,
                detections=fallback.detections,
                source=fallback.source,
                sha256=sha256,
                note=f"{note}; fallback={fallback.source}",
            )

    return clamscan_lookup(binary_path, sha256)


# --- History / integration --------------------------------------------------


def record_history(
    entry: dict[str, Any],
    history_path: Path = _DEFAULT_HISTORY_PATH,
) -> Path:
    """Append *entry* as one JSON line for trend analysis."""
    history_path = Path(history_path)
    history_path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(entry)
    payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    with history_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, sort_keys=True) + "\n")
    return history_path


def run_full_measurement(
    binary_path: Path,
    *,
    vt_api_key: str | None = None,
    history_path: Path | None = _DEFAULT_HISTORY_PATH,
    av_target: int = 5,
) -> dict[str, Any]:
    """Convenience wrapper that runs all 3 measurements and records history."""
    binary_path = Path(binary_path)
    av = measure_av_signatures(binary_path, vt_api_key=vt_api_key)
    strings_result = analyze_strings(binary_path)
    entropy_result = measure_entropy(binary_path)

    report = {
        "binary": str(binary_path),
        "sha256": av.sha256,
        "av": av.as_dict(),
        "strings": strings_result.as_dict(),
        "entropy": entropy_result.as_dict(),
        "target_max_av_detections": av_target,
        "target_met": av.detected_count < av_target,
    }
    if history_path is not None:
        record_history(report, history_path=history_path)
    return report


def summarize_history(
    history_path: Path = _DEFAULT_HISTORY_PATH,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Return the most recent *limit* history entries (oldest first)."""
    history_path = Path(history_path)
    if not history_path.exists():
        return []
    lines = history_path.read_text(encoding="utf-8").splitlines()
    entries: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


__all__ = [
    "AVScanResult",
    "Detection",
    "EntropyResult",
    "StringAnalysis",
    "SUSPICIOUS_STRING_PATTERNS",
    "analyze_strings",
    "measure_av_signatures",
    "measure_entropy",
    "record_history",
    "run_full_measurement",
    "summarize_history",
]
