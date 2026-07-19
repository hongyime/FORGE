"""
forge/phase3/__init__.py
Evasion & Payload Generation — public API surface.

Import paths are kept stable; internal module names may change.
All heavy imports are deferred to avoid slowing CLI startup.
"""
from __future__ import annotations


def __getattr__(name: str):
    if name == "ObfuscationEngine":
        from forge.phase3.obfuscator import ObfuscationEngine
        return ObfuscationEngine
    if name == "ObfuscationCriterion":
        from forge.phase3.obfuscator import ObfuscationCriterion
        return ObfuscationCriterion
    if name == "EncodingChain":
        from forge.phase3.payload_builder import EncodingChain
        return EncodingChain
    if name == "PayloadBuilder":
        from forge.phase3.payload_builder import PayloadBuilder
        return PayloadBuilder
    if name == "LOTSStager":
        from forge.phase3.lots_stager import LOTSStager
        return LOTSStager
    if name == "exponential_backoff":
        from forge.phase3.backoff import exponential_backoff
        return exponential_backoff
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "EncodingChain",
    "LOTSStager",
    "ObfuscationCriterion",
    "ObfuscationEngine",
    "PayloadBuilder",
    "exponential_backoff",
]
