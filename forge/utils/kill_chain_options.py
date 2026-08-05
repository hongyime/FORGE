from __future__ import annotations


def normalize_kill_chain_max_iter(value: object, *, default: int = 15) -> int:
    if value in (None, ""):
        candidate = default
    else:
        try:
            candidate = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("max_iter must be an integer.") from exc
    if candidate < 1 or candidate > 20:
        raise ValueError("max_iter must be between 1 and 20.")
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
