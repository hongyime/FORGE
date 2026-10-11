"""Universal tool-wrapper primitives.

Backlog item: Do Next #17 — Strix-style universal tool-wrapper hardening
Research: ``docs/competitive_research_strix_cairn_muraena.md`` §1.2, §5.4 Wave 1.

The wrappers in this module exist so every connector/tool subprocess output
and every tool function call passes through the same deterministic guards
before entering a downstream parser, dashboard, LLM context window, or
audit record. The guarantees are:

* :func:`bounded_output` caps string output by line count AND byte count
  before any parser sees it, replacing the removed tail with a stable
  ``[TRUNCATED: ...]`` marker. This prevents gigabyte scanner stdout from
  flooding a parser or an LLM prompt.
* :func:`coerce_arguments` normalises common LLM-produced schema violations
  such as ``"null"`` strings, strings-when-array-expected, JSON-string-in-
  dict, and numeric strings. The caller still owns semantic validation.
* :func:`safe_tool_call` wraps any tool function so uncaught exceptions
  become structured string results (``error-as-result``) instead of
  propagating up and killing the connector run or kill-chain loop.

The wrappers are deterministic, local-only, allocate at most ``max_bytes``
output per call, and never execute, log, or forward sensitive values —
they operate purely on the data already in memory.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

__all__ = [
    "DEFAULT_MAX_LINES",
    "DEFAULT_MAX_BYTES",
    "bounded_output",
    "coerce_arguments",
    "safe_tool_call",
]

# Public defaults — matched by callers like the connector runner and
# phase4 parsers. Change deliberately; downstream parsers assume a stable
# ceiling.
DEFAULT_MAX_LINES = 500
DEFAULT_MAX_BYTES = 50_000

_TRUNCATION_FOOTER_RESERVE = 128  # worst-case marker length budget.


def bounded_output(
    result: Any,
    *,
    max_lines: int = DEFAULT_MAX_LINES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> str:
    """Cap arbitrary tool output before it reaches a parser or LLM context.

    The input is normalised to text first. ``bytes`` are decoded using
    ``utf-8`` with ``replace`` so partial or corrupt scanner output does
    not raise. ``list``/``tuple`` of lines are joined with ``\\n``. Any
    other type is converted via ``str``.

    Truncation applies the stricter of ``max_lines`` and ``max_bytes``.
    When truncation occurs, the trailing content is replaced by a stable
    marker:

        ``[TRUNCATED: <original_lines> lines -> <max_lines>]``

    Parameters
    ----------
    result:
        Raw tool output. ``str``, ``bytes``, iterable of strings, or any
        other object (converted via ``str``).
    max_lines:
        Maximum number of lines to preserve. Must be ``>= 1``.
    max_bytes:
        Maximum number of UTF-8 bytes to preserve, including the
        truncation marker. Must be ``>= 1``.

    Returns
    -------
    str
        A capped UTF-8 string safe to feed to any downstream parser.
    """

    max_lines = max(1, int(max_lines))
    max_bytes = max(1, int(max_bytes))

    text = _coerce_to_text(result)
    if not text:
        return ""

    original_lines = text.count("\n") + (0 if text.endswith("\n") else 1)
    truncated = False
    kept_text = text
    kept_line_count = original_lines

    # Line cap first — cheap check, bounds the subsequent byte scan.
    if original_lines > max_lines:
        lines = text.splitlines()
        kept_text = "\n".join(lines[:max_lines])
        kept_line_count = max_lines
        truncated = True

    # Byte cap after line cap.
    encoded = kept_text.encode("utf-8", errors="replace")
    if len(encoded) > max_bytes:
        truncated = True
        budget = max(1, max_bytes - _TRUNCATION_FOOTER_RESERVE)
        clipped = encoded[:budget]
        # Avoid splitting a multi-byte UTF-8 code point.
        kept_text = clipped.decode("utf-8", errors="ignore")
        kept_line_count = kept_text.count("\n") + (
            0 if kept_text.endswith("\n") or not kept_text else 1
        )

    if not truncated:
        return kept_text

    marker = f"[TRUNCATED: {original_lines} lines -> {max_lines}]"
    joiner = "" if not kept_text or kept_text.endswith("\n") else "\n"
    return f"{kept_text}{joiner}{marker}"


def coerce_arguments(
    args: Mapping[str, Any] | None,
    schema: Mapping[str, Mapping[str, Any]] | None,
) -> dict[str, Any]:
    """Normalise LLM-produced schema violations into typed Python values.

    LLM tool-call providers routinely emit arguments that do not strictly
    match a declared JSON schema. The common failure modes are:

    * ``"null"`` as a string when ``None`` is intended.
    * A plain string when the schema expects an array (``"a"`` → ``["a"]``).
    * A JSON-serialised string when the schema expects a dict/list.
    * Numeric values rendered as strings (``"42"`` → ``42``).
    * Boolean values rendered as strings (``"true"`` → ``True``).

    This function returns a NEW dict with those common slips normalised.
    Unknown keys are preserved verbatim. Keys declared in ``schema`` but
    missing from ``args`` are left out — downstream validation chooses
    whether to supply defaults.

    Parameters
    ----------
    args:
        Argument map produced by an LLM/tool caller. ``None`` is treated
        as empty.
    schema:
        Mapping of ``{argument_name: {"type": "<type>"}}`` where
        ``<type>`` is one of ``string``, ``array``, ``object``/``dict``,
        ``integer``/``int``, ``number``/``float``, ``boolean``/``bool``.
        Items without a known type are forwarded unchanged.

    Returns
    -------
    dict[str, Any]
        A normalised dict safe to pass to a tool function.
    """

    if not args:
        return {}
    args_map: dict[str, Any] = dict(args)
    schema_map: dict[str, Mapping[str, Any]] = dict(schema or {})

    coerced: dict[str, Any] = {}
    for key, value in args_map.items():
        spec = schema_map.get(key)
        if not spec:
            coerced[key] = value
            continue
        declared_type = str(spec.get("type") or "").strip().lower()
        coerced[key] = _coerce_single(value, declared_type)
    return coerced


def safe_tool_call(
    func: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Invoke ``func`` and turn uncaught exceptions into string results.

    Strix's tool-wrapper doctrine: no tool exception should kill the
    connector loop or kill-chain. The outer loop should always see a
    result — successful payload OR a redacted error string. The caller
    inspects the return value and decides whether to retry, surface the
    error to the operator, or continue past it.

    Returns the function's own return value on success. On failure,
    returns a string ``"error: <ExceptionType>: <message>"`` where
    ``<message>`` is bounded to 240 characters and freed of newlines so a
    nested error cannot escape the single-line envelope.

    ``KeyboardInterrupt`` and ``SystemExit`` deliberately propagate so
    operators can still interrupt a hung tool.
    """

    try:
        return func(*args, **kwargs)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # noqa: BLE001 - error-as-result is the point.
        return _format_error_result(exc)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _coerce_to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, bytearray):
        return bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, (list, tuple)):
        return "\n".join(_coerce_to_text(item) for item in value)
    return str(value)


def _coerce_single(value: Any, declared_type: str) -> Any:
    if declared_type in {"string", "str"}:
        return _coerce_string(value)
    if declared_type in {"array", "list"}:
        return _coerce_array(value)
    if declared_type in {"object", "dict", "mapping"}:
        return _coerce_dict(value)
    if declared_type in {"integer", "int"}:
        return _coerce_int(value)
    if declared_type in {"number", "float"}:
        return _coerce_float(value)
    if declared_type in {"boolean", "bool"}:
        return _coerce_bool(value)
    if declared_type == "null":
        return None if _is_null_literal(value) else value
    return value


def _is_null_literal(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"null", "none", ""}
    return False


def _coerce_string(value: Any) -> Any:
    if _is_null_literal(value):
        return None if value is None else value  # keep "" verbatim
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return str(value)


def _coerce_array(value: Any) -> Any:
    if _is_null_literal(value):
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, set):
        return sorted(value) if all(isinstance(item, str) for item in value) else list(value)
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = json.loads(text)
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, list):
                return parsed
        # Comma-separated fallback.
        if "," in text:
            return [item.strip() for item in text.split(",") if item.strip()]
        return [text]
    return [value]


def _coerce_dict(value: Any) -> Any:
    if _is_null_literal(value):
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        if text.startswith("{") and text.endswith("}"):
            try:
                parsed = json.loads(text)
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, dict):
                return parsed
    return value


def _coerce_int(value: Any) -> Any:
    if _is_null_literal(value):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if "." in text or "e" in text.lower():
                return int(float(text))
            return int(text, 10)
        except (TypeError, ValueError):
            return value
    return value


def _coerce_float(value: Any) -> Any:
    if _is_null_literal(value):
        return None
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return float(text)
        except (TypeError, ValueError):
            return value
    return value


def _coerce_bool(value: Any) -> Any:
    if _is_null_literal(value):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"true", "yes", "y", "on", "1"}:
            return True
        if text in {"false", "no", "n", "off", "0"}:
            return False
    return value


def _format_error_result(exc: BaseException) -> str:
    kind = type(exc).__name__
    raw_message = str(exc)
    message = " ".join(raw_message.replace("\r", " ").replace("\n", " ").split())
    if len(message) > 240:
        message = message[:237] + "..."
    return f"error: {kind}: {message}" if message else f"error: {kind}"
