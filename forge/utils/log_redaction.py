"""forge/utils/log_redaction.py — logging filter that redacts secret query params.

The httpx / httpcore / urllib3 loggers emit request URLs at DEBUG/INFO/WARNING
level. When those URLs carry credentials as query parameters (Shodan
``?key=``, GitHub ``?access_token=``, GCS/AWS SigV4, Azure SAS, etc.) the
secret leaks into every log destination — stdout, journalctl, file handlers,
and any downstream log aggregator.

This module ships a ``SecretQueryRedactionFilter`` that rewrites the emitted
message in place. It reuses ``_QUERY_SECRET_RE`` from
:mod:`forge.utils.validation_summary` so the token list stays canonical.

Install once at CLI / worker startup via :func:`install_query_redaction_filter`.
"""

from __future__ import annotations

import logging
from typing import Iterable

from forge.utils.validation_summary import _QUERY_SECRET_RE


_DEFAULT_TARGET_LOGGERS: tuple[str, ...] = (
    "httpx",
    "httpcore",
    "urllib3",
    "requests",
)


class SecretQueryRedactionFilter(logging.Filter):
    """Redact secret query parameters from every log record it sees.

    Applied to the module-level logger only; child loggers inherit the filter
    via standard :mod:`logging` propagation rules.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Rewrite the formatted message first — this is what most log
        # handlers actually emit. LogRecord.msg may contain %-format tokens
        # so we also scrub the args tuple defensively.
        try:
            rendered = record.getMessage()
        except Exception:  # noqa: BLE001 — defensive; never drop a record
            rendered = str(record.msg)
        redacted = _QUERY_SECRET_RE.sub(
            lambda match: f"{match.group(1)}[REDACTED]",
            rendered,
        )
        if redacted != rendered:
            record.msg = redacted
            record.args = ()
            return True

        # No secret in the rendered message — still scrub raw args in case
        # a downstream Formatter re-renders them differently.
        if record.args:
            new_args: list[object] = []
            changed = False
            for value in _iter_args(record.args):
                if isinstance(value, str):
                    scrubbed = _QUERY_SECRET_RE.sub(
                        lambda match: f"{match.group(1)}[REDACTED]",
                        value,
                    )
                    if scrubbed != value:
                        changed = True
                    new_args.append(scrubbed)
                else:
                    new_args.append(value)
            if changed:
                record.args = tuple(new_args)
        return True


def _iter_args(args: object) -> Iterable[object]:
    """Yield each arg from either a tuple or a single-value form."""
    if isinstance(args, tuple):
        yield from args
    else:
        yield args


def install_query_redaction_filter(
    logger_names: Iterable[str] = _DEFAULT_TARGET_LOGGERS,
) -> SecretQueryRedactionFilter:
    """Attach :class:`SecretQueryRedactionFilter` to the given loggers.

    Idempotent — safe to call multiple times; the same filter instance is
    added once per named logger. Returns the shared filter instance so
    callers can attach it to additional loggers if needed.
    """
    redactor = SecretQueryRedactionFilter()
    for name in logger_names:
        target = logging.getLogger(name)
        # Only attach once per logger; check by class rather than identity
        # since callers may re-import the module.
        already_installed = any(
            isinstance(existing, SecretQueryRedactionFilter)
            for existing in target.filters
        )
        if not already_installed:
            target.addFilter(redactor)
    return redactor
