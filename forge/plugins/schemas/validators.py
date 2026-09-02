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
from typing import Any, Final, Literal

import jsonschema
from jsonschema import Draft202012Validator

from forge.plugins.schemas.event_schema import (
    EVENT_SCHEMAS,
    FORBIDDEN_FIELDS,
    MAX_PAYLOAD_BYTES,
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
    event_type: Draft202012Validator(schema)
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
            if key_str.lower() in FORBIDDEN_FIELDS:
                hits.append(child_path)
            _scan_forbidden(child, child_path, hits)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            child_path = f"{path}[{idx}]"
            _scan_forbidden(child, child_path, hits)


# ---------------------------------------------------------------------------
# Payload size
# ---------------------------------------------------------------------------


def validate_payload_size(payload: dict[str, Any], max_bytes: int = MAX_PAYLOAD_BYTES) -> bool:
    """Return True iff the JSON-serialized *payload* is at most *max_bytes*.

    Serialization uses ``json.dumps`` with the default separators; if the
    payload is not JSON-serializable, this function returns False rather
    than raising - the caller wanted a boolean check.
    """
    try:
        encoded = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    except (TypeError, ValueError):
        return False
    return len(encoded) <= max_bytes


def _payload_byte_size(payload: dict[str, Any]) -> int | None:
    try:
        return len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))
    except (TypeError, ValueError):
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

    # Structural schema check (required fields, types, additionalProperties).
    schema_errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
    for err in schema_errors:
        errors.append(_format_schema_error(err))

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
]
