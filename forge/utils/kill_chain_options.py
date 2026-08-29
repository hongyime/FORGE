from __future__ import annotations


def normalize_kill_chain_max_iter(value: object, *, default: int = 7) -> int:
    if value in (None, ""):
        candidate = default
    else:
        try:
            candidate = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("max_iter must be an integer.") from exc
    if candidate < 1 or candidate > 10:
        raise ValueError("max_iter must be between 1 and 10.")
    return candidate


def _normalize_bounded_int(
    value: object,
    *,
    default: int,
    minimum: int,
    maximum: int,
    label: str,
) -> int:
    if value in (None, ""):
        candidate = default
    else:
        try:
            candidate = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label} must be an integer.") from exc
    if candidate < minimum or candidate > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}.")
    return candidate


def normalize_kill_chain_synthesis_depth(value: object, *, default: int = 3) -> int:
    return _normalize_bounded_int(
        value,
        default=default,
        minimum=1,
        maximum=5,
        label="synthesis_depth",
    )


def normalize_kill_chain_validation_batch_limit(value: object, *, default: int = 16) -> int:
    return _normalize_bounded_int(
        value,
        default=default,
        minimum=1,
        maximum=64,
        label="validation_batch_limit",
    )


def normalize_kill_chain_max_runtime_minutes(value: object, *, default: int = 25) -> int:
    return _normalize_bounded_int(
        value,
        default=default,
        minimum=1,
        maximum=1440,
        label="max_runtime_minutes",
    )
