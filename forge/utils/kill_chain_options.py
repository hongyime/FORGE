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
