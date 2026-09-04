"""Tests for E3.3 detection-surface measurement (DEFENSIVE POSTURE).

Covers:
  * AV scan returns a well-shaped detection count (VirusTotal + ClamAV paths)
  * String analysis flags suspicious tokens like ``password``/``dump``/``inject``
  * Shannon entropy is correct for known inputs and flags high-entropy blobs
  * History JSONL round-trips through ``record_history`` / ``summarize_history``
"""

from __future__ import annotations

import json
import math
import os
import secrets
from pathlib import Path

import pytest

from forge.security.detection_surface import (
    AVScanResult,
    Detection,
    _parse_vt_response,
    analyze_strings,
    measure_av_signatures,
    measure_entropy,
    record_history,
    run_full_measurement,
    summarize_history,
)


# --- fixtures ---------------------------------------------------------------


@pytest.fixture()
def clean_binary(tmp_path: Path) -> Path:
    """A harmless payload with only innocuous strings."""
    p = tmp_path / "clean.bin"
    p.write_bytes(b"hello world\x00this is fine\x00forge toolkit v7\x00" * 40)
    return p


@pytest.fixture()
def suspicious_binary(tmp_path: Path) -> Path:
    """Payload that includes several trigger strings."""
    p = tmp_path / "sus.bin"
    p.write_bytes(
        b"BEGIN\x00please_dump_password_now\x00"
        b"inject_shellcode_into_lsass\x00"
        b"VirtualAlloc\x00CreateRemoteThread\x00END\x00"
    )
    return p


@pytest.fixture()
def high_entropy_binary(tmp_path: Path) -> Path:
    p = tmp_path / "packed.bin"
    p.write_bytes(secrets.token_bytes(256 * 1024))
    return p


# --- string analysis --------------------------------------------------------


class TestAnalyzeStrings:
    def test_flags_suspicious_patterns(self, suspicious_binary: Path) -> None:
        result = analyze_strings(suspicious_binary)
        assert result.total_strings > 0
        assert len(result.suspicious_strings) >= 3
        matched = set(result.matched_patterns)
        # Multiple pattern families must fire.
        assert {"password", "inject"}.issubset(matched)
        assert "virtualalloc" in matched
        # Detected strings are redacted to sha256:<16hex> tokens; the category
        # signal lives in matched_patterns, and plaintext must NEVER leak.
        for token in result.suspicious_strings:
            assert token.startswith("sha256:")
            assert len(token) == len("sha256:") + 16
        joined = "\n".join(result.suspicious_strings).lower()
        assert "password" not in joined
        assert "shellcode" not in joined

    def test_clean_binary_has_no_matches(self, clean_binary: Path) -> None:
        result = analyze_strings(clean_binary)
        assert result.total_strings > 0
        assert result.suspicious_strings == ()
        assert result.matched_patterns == ()

    def test_custom_patterns(self, tmp_path: Path) -> None:
        p = tmp_path / "custom.bin"
        p.write_bytes(b"\x00zzz_specific_marker_xyz\x00")
        result = analyze_strings(p, patterns=("specific_marker",))
        assert result.matched_patterns == ("specific_marker",)
        # Category is proved by matched_patterns; suspicious_strings stays hashed.
        assert all(s.startswith("sha256:") for s in result.suspicious_strings)

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            analyze_strings(tmp_path / "nope.bin")


# --- entropy ----------------------------------------------------------------


class TestMeasureEntropy:
    def test_constant_bytes_has_zero_entropy(self, tmp_path: Path) -> None:
        p = tmp_path / "flat.bin"
        p.write_bytes(b"\x41" * 4096)
        r = measure_entropy(p)
        assert r.entropy_score == pytest.approx(0.0, abs=1e-9)
        assert r.is_suspicious is False
        assert r.byte_count == 4096

    def test_two_symbol_uniform_is_one_bit(self, tmp_path: Path) -> None:
        p = tmp_path / "twosym.bin"
        p.write_bytes(b"\x00\xff" * 4096)
        r = measure_entropy(p)
        assert r.entropy_score == pytest.approx(1.0, abs=1e-6)
        assert r.is_suspicious is False

    def test_random_bytes_flagged_suspicious(
        self, high_entropy_binary: Path,
    ) -> None:
        r = measure_entropy(high_entropy_binary)
        assert r.entropy_score > 7.5
        assert r.entropy_score <= math.log2(256) + 1e-9
        assert r.is_suspicious is True

    def test_empty_file(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        r = measure_entropy(p)
        assert r.entropy_score == 0.0
        assert r.byte_count == 0
        assert r.is_suspicious is False

    def test_threshold_override(self, tmp_path: Path) -> None:
        p = tmp_path / "twosym.bin"
        p.write_bytes(b"\x00\xff" * 4096)
        # Force a very low threshold - now the same content flags suspicious.
        r = measure_entropy(p, threshold=0.5)
        assert r.is_suspicious is True


# --- AV signatures ----------------------------------------------------------


def _fake_vt_payload(malicious: int, total: int, *, engine: str = "TestAV") -> dict:
    results: dict = {}
    for i in range(malicious):
        name = engine if i == 0 else f"{engine}{i}"
        results[name] = {"category": "malicious", "result": "Trojan.Generic"}
    # Pad with undetected engines so total_engines is meaningful.
    for i in range(total - malicious):
        results[f"Engine{i}"] = {"category": "undetected", "result": None}
    return {
        "data": {
            "attributes": {
                "last_analysis_results": results,
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": 0,
                    "undetected": total - malicious,
                    "harmless": 0,
                    "timeout": 0,
                    "type-unsupported": 0,
                },
            }
        }
    }


class TestMeasureAvSignatures:
    def test_virustotal_path_counts_detections(self, clean_binary: Path) -> None:
        def fake_vt(sha256: str, api_key: str) -> AVScanResult:
            assert api_key == "test-key"
            assert len(sha256) == 64
            return _parse_vt_response(sha256, _fake_vt_payload(2, 72))

        r = measure_av_signatures(
            clean_binary, vt_api_key="test-key", vt_lookup=fake_vt,
        )
        assert r.source == "virustotal"
        assert r.total_engines == 72
        assert r.detected_count == 2
        assert len(r.detections) == 2
        assert all(isinstance(d, Detection) for d in r.detections)
        assert r.detections[0].engine == "TestAV"

    def test_clamscan_fallback_when_vt_fails(self, clean_binary: Path) -> None:
        def fake_vt(sha256: str, api_key: str) -> AVScanResult:
            raise RuntimeError("boom")

        def fake_clam(binary_path: Path, sha256: str) -> AVScanResult:
            return AVScanResult(
                total_engines=1, detected_count=0, detections=(),
                source="clamav", sha256=sha256, note="rc=0 clean",
            )

        r = measure_av_signatures(
            clean_binary, vt_api_key="test-key",
            vt_lookup=fake_vt, clamscan_lookup=fake_clam,
        )
        assert r.source == "clamav"
        assert "VirusTotal lookup failed" in r.note

    def test_no_backend_available_returns_placeholder(
        self, clean_binary: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("FORGE_VT_API_KEY", raising=False)

        def fake_clam(binary_path: Path, sha256: str) -> AVScanResult:
            return AVScanResult(
                total_engines=0, detected_count=0, detections=(),
                source="none", sha256=sha256,
                note="clamscan not on PATH and no VirusTotal key",
            )

        r = measure_av_signatures(clean_binary, clamscan_lookup=fake_clam)
        assert r.source == "none"
        assert r.total_engines == 0
        assert r.detected_count == 0
        assert "not on PATH" in r.note

    def test_reads_vt_key_from_env(
        self, clean_binary: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seen: dict[str, str] = {}

        def fake_vt(sha256: str, api_key: str) -> AVScanResult:
            seen["key"] = api_key
            return _parse_vt_response(sha256, _fake_vt_payload(0, 70))

        monkeypatch.setenv("FORGE_VT_API_KEY", "env-key-123")
        r = measure_av_signatures(clean_binary, vt_lookup=fake_vt)
        assert seen["key"] == "env-key-123"
        assert r.source == "virustotal"
        assert r.detected_count == 0

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            measure_av_signatures(tmp_path / "nope.bin")


# --- history + integration --------------------------------------------------


class TestHistoryAndIntegration:
    def test_record_and_summarize(self, tmp_path: Path) -> None:
        history = tmp_path / "hist.jsonl"
        record_history({"run": 1, "detected": 2}, history_path=history)
        record_history({"run": 2, "detected": 4}, history_path=history)
        entries = summarize_history(history_path=history)
        assert [e["run"] for e in entries] == [1, 2]
        assert all("timestamp" in e for e in entries)

    def test_summarize_missing_file(self, tmp_path: Path) -> None:
        assert summarize_history(history_path=tmp_path / "none.jsonl") == []

    def test_run_full_measurement_records_history(
        self,
        suspicious_binary: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("FORGE_VT_API_KEY", raising=False)
        history = tmp_path / "hist.jsonl"

        # Force the AV path to a deterministic no-backend placeholder.
        def fake_clam(binary_path: Path, sha256: str) -> AVScanResult:
            return AVScanResult(
                total_engines=0, detected_count=0, detections=(),
                source="none", sha256=sha256, note="stub",
            )
        monkeypatch.setattr(
            "forge.security.detection_surface._clamscan_lookup", fake_clam,
        )

        report = run_full_measurement(
            suspicious_binary, history_path=history, av_target=5,
        )
        assert report["target_met"] is True
        assert report["strings"]["matched_patterns"]
        assert 0.0 < report["entropy"]["entropy_score"] < 8.0
        assert report["av"]["detected_count"] == 0

        raw = history.read_text(encoding="utf-8").splitlines()
        assert len(raw) == 1
        payload = json.loads(raw[0])
        assert payload["sha256"] == report["sha256"]
        assert payload["target_max_av_detections"] == 5

    def test_target_not_met_when_detections_high(
        self,
        clean_binary: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def fake_clam(binary_path: Path, sha256: str) -> AVScanResult:
            return AVScanResult(
                total_engines=1, detected_count=9, detections=(
                    Detection(engine="clamav", category="malicious",
                              result="Trojan.Test"),
                ), source="clamav", sha256=sha256, note="rc=1",
            )
        monkeypatch.setattr(
            "forge.security.detection_surface._clamscan_lookup", fake_clam,
        )
        monkeypatch.delenv("FORGE_VT_API_KEY", raising=False)

        report = run_full_measurement(
            clean_binary,
            history_path=tmp_path / "hist.jsonl",
            av_target=5,
        )
        assert report["av"]["detected_count"] == 9
        assert report["target_met"] is False
