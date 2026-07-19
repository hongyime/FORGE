"""
forge/audit/verifier.py - Hash-chain integrity verifier for AuditLogger JSONL.

Reads an audit JSONL file written by :class:`forge.audit.logger.AuditLogger`
with ``hash_chain=True`` and verifies that:

  * Every line is a valid JSON object with the wrapper schema
    ``{"entry": ..., "prev_hash": ..., "entry_hash": ...}``.
  * Each line's ``prev_hash`` equals the previous line's ``entry_hash``
    (or the all-zero genesis on the first line).
  * Each line's ``entry_hash`` equals
    ``sha256(prev_hash || canonical_json(entry)).hexdigest()``.

Returns a :class:`VerificationResult`. The first failed line short-circuits
verification - the rest of the chain is unverifiable once a tamper is found.

Usage:
    >>> result = verify_audit_log(Path("audit.jsonl"))
    >>> assert result.ok, result.failure_reason
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

__all__ = ["VerificationResult", "verify_audit_log"]


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    lines_checked: int
    failure_line: int | None = None
    failure_reason: str | None = None


def verify_audit_log(path: Path | str) -> VerificationResult:
    """Verify the hash chain of an audit JSONL file."""
    p = Path(path)
    if not p.exists():
        return VerificationResult(
            ok=False, lines_checked=0,
            failure_line=None, failure_reason=f"file not found: {p}",
        )

    expected_prev = "0" * 64
    line_no = 0

    with p.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line_no += 1
            raw = raw.strip()
            if not raw:
                continue
            try:
                wrapper = json.loads(raw)
            except json.JSONDecodeError as exc:
                return VerificationResult(
                    ok=False, lines_checked=line_no,
                    failure_line=line_no,
                    failure_reason=f"invalid JSON: {exc}",
                )

            if not isinstance(wrapper, dict) or not {
                "entry", "prev_hash", "entry_hash",
            } <= set(wrapper):
                return VerificationResult(
                    ok=False, lines_checked=line_no,
                    failure_line=line_no,
                    failure_reason="missing wrapper keys (entry/prev_hash/entry_hash)",
                )

            stated_prev = str(wrapper["prev_hash"])
            stated_hash = str(wrapper["entry_hash"])
            entry_obj = wrapper["entry"]

            if stated_prev != expected_prev:
                return VerificationResult(
                    ok=False, lines_checked=line_no,
                    failure_line=line_no,
                    failure_reason=(
                        f"prev_hash mismatch: expected {expected_prev[:12]}..., "
                        f"got {stated_prev[:12]}..."
                    ),
                )

            # Recompute entry_hash. We dump the entry sub-object using the same
            # canonical separators Pydantic + json use to keep determinism.
            entry_json = json.dumps(entry_obj, separators=(",", ":"))
            # AuditLogger uses Pydantic .model_dump_json() which emits identical
            # bytes to json.dumps(separators=(",", ":")) for our schema, but we
            # match more leniently below to tolerate small whitespace shifts.
            chained_a = (stated_prev + entry_json).encode("utf-8")
            recomputed = hashlib.sha256(chained_a).hexdigest()
            if recomputed != stated_hash:
                # Re-attempt with sort_keys=True in case the writer was using
                # a slightly different dump order.
                entry_json_sorted = json.dumps(entry_obj, sort_keys=True, separators=(",", ":"))
                chained_b = (stated_prev + entry_json_sorted).encode("utf-8")
                if hashlib.sha256(chained_b).hexdigest() != stated_hash:
                    return VerificationResult(
                        ok=False, lines_checked=line_no,
                        failure_line=line_no,
                        failure_reason=(
                            f"entry_hash mismatch: stated {stated_hash[:12]}..., "
                            f"computed {recomputed[:12]}..."
                        ),
                    )

            expected_prev = stated_hash

    return VerificationResult(ok=True, lines_checked=line_no)
