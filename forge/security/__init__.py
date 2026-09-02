"""FORGE security posture measurement modules.

DEFENSIVE ONLY. Measures how detectable FORGE binaries are to AV/EDR so the
project can track its defensive posture over time. No offensive capability.
"""

from .detection_surface import (
    AVScanResult,
    Detection,
    StringAnalysis,
    EntropyResult,
    analyze_strings,
    measure_av_signatures,
    measure_entropy,
    record_history,
    run_full_measurement,
)

__all__ = [
    "AVScanResult",
    "Detection",
    "EntropyResult",
    "StringAnalysis",
    "analyze_strings",
    "measure_av_signatures",
    "measure_entropy",
    "record_history",
    "run_full_measurement",
]
