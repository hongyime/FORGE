"""Validation for plugin event bus events (E2.3).

This module enforces the boundary contract:

    1. Event has a known ``event_type`` and matching JSON Schema.
    2. Required fields present; typed correctly; no unexpected fields.
    3. No forbidden field names anywhere in the payload (passwords,
       api keys, tokens, ...), case-insensitive, at every nesting depth.
    4. Serialized payload size does not exceed ``MAX_PAYLOAD_BYTES``.

The middleware supports two modes:

    - ``strict``  -> raises ``SchemaValidationError`` on the first failure
    - ``lenient`` -> logs and drops the offending event; caller receives
                     ``ValidationResult(valid=False, ...)``

Silent drops are never allowed: every rejection is logged with the
field name and reason.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Final, Literal

import jsonschema
from jsonschema import Draft202012Validator, FormatChecker

from forge.plugins.schemas.event_schema import (
    EVENT_SCHEMAS,
    FORBIDDEN_FIELD_PATTERNS,
    MAX_NESTING_DEPTH,
    MAX_PAYLOAD_BYTES,
    MAX_PAYLOAD_KEYS,
)

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

Mode = Literal["strict", "lenient"]


# ---------------------------------------------------------------------------
# Public value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Outcome of validating a single event.

    Attributes:
        valid: True iff the event passed every check.
        errors: One string per failure. Each message names the offending
            field (dotted path where applicable) and the reason.
        event_type: Discriminator recovered from the event (may be empty
            string when the event lacked the field).
    """

    valid: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
    event_type: str = ""

    def __bool__(self) -> bool:  # convenience for `if result:`
        return self.valid


class SchemaValidationError(Exception):
    """Raised in strict mode when an event fails validation.

    Attributes:
        errors: Tuple of human-readable failure reasons.
        event_type: Recovered discriminator, or empty string.
    """

    def __init__(self, errors: tuple[str, ...], event_type: str = "") -> None:
        self.errors = errors
        self.event_type = event_type
        joined = "; ".join(errors) if errors else "unknown validation failure"
        super().__init__(f"event validation failed ({event_type or 'unknown'}): {joined}")


# ---------------------------------------------------------------------------
# Compiled schema validators (built once at import time)
# ---------------------------------------------------------------------------

_COMPILED_VALIDATORS: Final[dict[str, Draft202012Validator]] = {
    event_type: Draft202012Validator(schema, format_checker=FormatChecker())
    for event_type, schema in EVENT_SCHEMAS.items()
}


# ---------------------------------------------------------------------------
# Forbidden-field detection
# ---------------------------------------------------------------------------


def check_forbidden_fields(payload: dict[str, Any]) -> list[str]:
    """Return the dotted paths of every forbidden field found in *payload*.

    Matching is case-insensitive; nested dicts and lists are traversed.
    An empty list means the payload is clean.

    Examples:
        >>> check_forbidden_fields({"password": "x"})
        ['password']
        >>> check_forbidden_fields({"user": {"api_key": "x"}})
        ['user.api_key']
        >>> check_forbidden_fields({"items": [{"secret": 1}]})
        ['items[0].secret']
    """
    if not isinstance(payload, dict):
        return []

    hits: list[str] = []
    _scan_forbidden(payload, "", hits)
    return hits


def _scan_forbidden(value: Any, path: str, hits: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_str = str(key)
            child_path = f"{path}.{key_str}" if path else key_str
            if _key_matches_forbidden(key_str):
                hits.append(child_path)
            _scan_forbidden(child, child_path, hits)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            child_path = f"{path}[{idx}]"
            _scan_forbidden(child, child_path, hits)


def _key_matches_forbidden(key: str) -> bool:
    """Case-insensitive substring match against forbidden patterns (spec §4)."""
    lowered = key.lower()
    return any(pattern in lowered for pattern in FORBIDDEN_FIELD_PATTERNS)

# ---------------------------------------------------------------------------
# Payload size
# ---------------------------------------------------------------------------


def validate_payload_size(payload: dict[str, Any], max_bytes: int = MAX_PAYLOAD_BYTES) -> bool:
    """Return True iff the JSON-serialized *payload* is at most *max_bytes*.

    Serialization is strict JSON. Unsupported Python objects, circular values,
    and non-finite numbers return ``False`` rather than being stringified.
    """
    try:
        encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return False
    return len(encoded) <= max_bytes


def _payload_byte_size(payload: dict[str, Any]) -> int | None:
    try:
        return len(
            json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        )
    except (TypeError, ValueError, RecursionError):
        return None


def validate_payload_structure(payload: dict[str, Any]) -> tuple[str, ...]:
    """Return boundary violations for JSON types, key count, depth, and cycles."""
    errors: list[str] = []
    key_count = [0]
    _scan_payload_structure(
        payload,
        path="payload",
        depth=1,
        ancestors=set(),
        key_count=key_count,
        errors=errors,
    )
    return tuple(errors)


def _scan_payload_structure(
    value: Any,
    *,
    path: str,
    depth: int,
    ancestors: set[int],
    key_count: list[int],
    errors: list[str],
) -> None:
    if isinstance(value, (dict, list)):
        if depth > MAX_NESTING_DEPTH:
            errors.append(
                f"{path}: nesting depth {depth} exceeds limit of {MAX_NESTING_DEPTH}"
            )
            return
        marker = id(value)
        if marker in ancestors:
            errors.append(f"{path}: circular container reference is not valid JSON")
            return
        ancestors.add(marker)
        try:
            if isinstance(value, dict):
                for key, child in value.items():
                    if not isinstance(key, str):
                        errors.append(f"{path}: object key {key!r} is not a string")
                        child_path = f"{path}.{key!s}"
                    else:
                        child_path = f"{path}.{key}"
                    key_count[0] += 1
                    if key_count[0] == MAX_PAYLOAD_KEYS + 1:
                        errors.append(
                            f"payload: key count exceeds limit of {MAX_PAYLOAD_KEYS}"
                        )
                    _scan_payload_structure(
                        child,
                        path=child_path,
                        depth=depth + 1 if isinstance(child, (dict, list)) else depth,
                        ancestors=ancestors,
                        key_count=key_count,
                        errors=errors,
                    )
            else:
                for index, child in enumerate(value):
                    _scan_payload_structure(
                        child,
                        path=f"{path}[{index}]",
                        depth=depth + 1 if isinstance(child, (dict, list)) else depth,
                        ancestors=ancestors,
                        key_count=key_count,
                        errors=errors,
                    )
        finally:
            ancestors.remove(marker)
        return

    if value is None or isinstance(value, float) or not isinstance(
        value, (str, int, bool)
    ):
        errors.append(
            f"{path}: value of type {type(value).__name__} is not allowed by the JSON boundary"
        )


def _report_path_error(path: str) -> str | None:
    """Return a reason when a report path can escape the engagement workspace."""
    posix = PurePosixPath(path.replace("\\", "/"))
    windows = PureWindowsPath(path)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        return "path: must be relative to the engagement workspace"
    if ".." in posix.parts:
        return "path: parent traversal is not allowed"
    return None


# ---------------------------------------------------------------------------
# validate_event - the main entry point
# ---------------------------------------------------------------------------


def validate_event(event: dict[str, Any]) -> ValidationResult:
    """Validate a single event envelope against its schema.

    The envelope shape is::

        {
            "event_type": "<one of EVENT_SCHEMAS>",
            "payload":    { ... schema-conforming payload ... }
        }

    Returns a :class:`ValidationResult`. The function never raises; the
    caller decides how to react (strict mode via
    :class:`EventValidatorMiddleware`).
    """
    errors: list[str] = []

    if not isinstance(event, dict):
        return ValidationResult(
            valid=False,
            errors=(f"event: must be a dict, got {type(event).__name__}",),
            event_type="",
        )

    event_type = event.get("event_type", "")
    if not isinstance(event_type, str) or not event_type:
        errors.append("event_type: required field missing or not a string")
        return ValidationResult(valid=False, errors=tuple(errors), event_type="")

    validator = _COMPILED_VALIDATORS.get(event_type)
    if validator is None:
        errors.append(
            f"event_type: unknown value {event_type!r}; "
            f"expected one of {sorted(EVENT_SCHEMAS.keys())}"
        )
        return ValidationResult(valid=False, errors=tuple(errors), event_type=event_type)

    if "payload" not in event:
        errors.append("payload: required field missing")
        return ValidationResult(valid=False, errors=tuple(errors), event_type=event_type)

    payload = event["payload"]
    if not isinstance(payload, dict):
        errors.append(f"payload: must be an object, got {type(payload).__name__}")
        return ValidationResult(valid=False, errors=tuple(errors), event_type=event_type)

    boundary_errors = validate_payload_structure(payload)
    errors.extend(boundary_errors)

    # Avoid sending cyclic/over-depth values into jsonschema recursion.
    if not boundary_errors:
        schema_errors = sorted(
            validator.iter_errors(payload), key=lambda e: list(e.absolute_path)
        )
        for err in schema_errors:
            errors.append(_format_schema_error(err))

        if event_type == "report:generated" and isinstance(payload.get("path"), str):
            path_error = _report_path_error(payload["path"])
            if path_error is not None:
                errors.append(path_error)

    # Forbidden fields: collect ALL, not just the first.
    forbidden = check_forbidden_fields(payload)
    for hit in forbidden:
        errors.append(f"{hit}: forbidden field (secrets must not be published on the event bus)")

    # Payload size ceiling.
    size = _payload_byte_size(payload)
    if size is None:
        errors.append("payload: is not JSON-serializable")
    elif size > MAX_PAYLOAD_BYTES:
        errors.append(
            f"payload: size {size} bytes exceeds limit of {MAX_PAYLOAD_BYTES} bytes"
        )

    if errors:
        return ValidationResult(valid=False, errors=tuple(errors), event_type=event_type)
    return ValidationResult(valid=True, errors=(), event_type=event_type)


def _format_schema_error(err: jsonschema.ValidationError) -> str:
    """Render a jsonschema error as `<dotted.path>: <reason>`."""
    if err.validator == "required":
        # err.message looks like "'foo' is a required property"
        return f"payload: {err.message}"
    path_parts = [str(p) for p in err.absolute_path]
    location = ".".join(path_parts) if path_parts else "payload"
    return f"{location}: {err.message}"


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class EventValidatorMiddleware:
    """Validation gate for the plugin event bus.

    Wrap ``bus.publish`` with :meth:`process`; the middleware either
    forwards the event (valid) or rejects it (invalid). In ``strict``
    mode invalid events raise :class:`SchemaValidationError`; in
    ``lenient`` mode they are logged and dropped, and the caller learns
    via the returned :class:`ValidationResult` that ``valid is False``.

    Silent drops are impossible: every rejection is logged at WARNING.
    """

    def __init__(self, mode: Mode = "strict") -> None:
        if mode not in ("strict", "lenient"):
            raise ValueError(f"mode must be 'strict' or 'lenient', got {mode!r}")
        self._mode: Mode = mode

    @property
    def mode(self) -> Mode:
        return self._mode

    def process(self, event: dict[str, Any]) -> ValidationResult:
        """Validate *event*. In strict mode, raise on failure.

        Returns the :class:`ValidationResult` in every case where no
        exception is raised (i.e., always in lenient mode, and on
        success in strict mode).
        """
        result = validate_event(event)
        if result.valid:
            return result

        _LOGGER.warning(
            "event rejected: event_type=%s errors=%s",
            result.event_type or "<missing>",
            list(result.errors),
        )
        if self._mode == "strict":
            raise SchemaValidationError(result.errors, event_type=result.event_type)
        return result


__all__ = [
    "EventValidatorMiddleware",
    "SchemaValidationError",
    "ValidationResult",
    "check_forbidden_fields",
    "validate_event",
    "validate_payload_size",
    "validate_payload_structure",
]
