"""forge.ingestion.bloodhound_importer — ROE-gated BloodHound zip importer.

U1.5 scope-gate implementation. Every ``import_zip`` call:

1. Validates that ``engagement_id`` is a non-empty, non-``None`` string.
2. Validates that a :class:`ScopeManifest` was supplied at construction
   time and that its shape passes the ROE checks (non-empty ``roe_id``,
   at least one authorized scope entry, no global wildcards such as
   ``*``/``0.0.0.0/0``/``::/0``).
3. Emits exactly four audit event categories through the shared
   :class:`forge.audit.logger.AuditLogger`:

   * ``import_started``   -- before any zip read.
   * ``entity_imported``  -- one entry per entity type parsed.
   * ``import_completed`` -- after every file was processed.
   * ``import_failed``    -- on any recoverable/unrecoverable failure.

Every audit entry carries the ``engagement_id`` in ``input_params`` so
downstream reviewers can reconstruct the trail per engagement.

ROE violations raise a subclass of :class:`ROEViolation` before any bytes
are read from the zip. The importer never partially imports data when a
scope check fails.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from forge.audit.models import AuditEntry, AuditEventType

if TYPE_CHECKING:
    from forge.audit.logger import AuditLogger

__all__ = [
    "BloodHoundImporter",
    "ImportResult",
    "InvalidScopeManifestError",
    "MissingEngagementIdError",
    "MissingScopeManifestError",
    "ROEViolation",
    "ScopeManifest",
]

_LOG = logging.getLogger(__name__)

_TOOL_NAME = "bloodhound_importer"

# Sentinel values callers must not use as scope entries. Live scope gates
# reject the same set; keep it aligned with the README manifest example.
_FORBIDDEN_SCOPE_TOKENS: frozenset[str] = frozenset({
    "*",
    "**",
    "*.*",
    "0.0.0.0/0",
    "::/0",
})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ROEViolation(Exception):
    """Base class for every ROE / scope-manifest rejection.

    Every subclass names the exact ROE requirement that was violated so
    the caller can surface it to the operator without introspecting the
    exception type.
    """


class MissingEngagementIdError(ROEViolation):
    """Raised when ``engagement_id`` is missing, empty, or not a string."""


class MissingScopeManifestError(ROEViolation):
    """Raised when the importer was constructed without a scope manifest."""


class InvalidScopeManifestError(ROEViolation):
    """Raised when the supplied :class:`ScopeManifest` fails ROE validation."""


# ---------------------------------------------------------------------------
# Scope manifest
# ---------------------------------------------------------------------------


class ScopeManifest(BaseModel):
    """Engagement-scoped ROE manifest.

    A manifest is only accepted when:

    * ``roe_id`` is a non-empty, whitespace-stripped string.
    * At least one of ``domains``, ``ip_ranges``, ``urls``, or
      ``authorized_seeds`` contains a concrete entry.
    * No entry is a global wildcard (``*``, ``0.0.0.0/0``, ``::/0``).
    * Every ``ip_ranges`` entry parses via :func:`ipaddress.ip_network`.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    roe_id: str = Field(min_length=1, max_length=256)
    domains: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    authorized_seeds: list[str] = Field(default_factory=list)

    @field_validator("domains", "urls", "authorized_seeds", mode="after")
    @classmethod
    def _reject_broad_string_scope(cls, value: list[str]) -> list[str]:
        for entry in value:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError(f"scope entry must be a non-empty string, got {entry!r}")
            if entry.strip() in _FORBIDDEN_SCOPE_TOKENS:
                raise ValueError(
                    f"broad wildcard scope entry {entry!r} is forbidden; "
                    "declare explicit domains/URLs/seeds instead"
                )
        return value

    @field_validator("ip_ranges", mode="after")
    @classmethod
    def _validate_ip_ranges(cls, value: list[str]) -> list[str]:
        for entry in value:
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError(f"ip_ranges entry must be a non-empty string, got {entry!r}")
            if entry.strip() in _FORBIDDEN_SCOPE_TOKENS:
                raise ValueError(
                    f"broad CIDR scope entry {entry!r} is forbidden; "
                    "declare specific ranges instead"
                )
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR {entry!r}: {exc}") from exc
        return value


def _manifest_has_any_scope(manifest: ScopeManifest) -> bool:
    return bool(
        manifest.domains
        or manifest.ip_ranges
        or manifest.urls
        or manifest.authorized_seeds
    )


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImportResult:
    """Outcome of a single :meth:`BloodHoundImporter.import_zip` call."""

    success: bool
    engagement_id: str
    zip_path: str
    total_entities: int
    entities_by_type: dict[str, int] = field(default_factory=dict)
    duration_seconds: float = 0.0
    error: str | None = None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class BloodHoundImporter:
    """Scope-gated BloodHound zip importer.

    Args:
        scope_manifest: Declared engagement ROE manifest. ``None`` raises
            :class:`MissingScopeManifestError` immediately.
        audit_logger: Optional :class:`forge.audit.logger.AuditLogger`
            instance. When omitted the importer builds an in-memory
            logger so audit events are still captured (satisfies the
            "audit log entries must be written before any import action"
            rule even in test/CI contexts).

    Raises:
        MissingScopeManifestError: ``scope_manifest`` is ``None``.
        InvalidScopeManifestError: The manifest failed ROE validation.
    """

    def __init__(
        self,
        scope_manifest: ScopeManifest | None,
        audit_logger: "AuditLogger | None" = None,
    ) -> None:
        if scope_manifest is None:
            raise MissingScopeManifestError(
                "ROE requirement failed: scope_manifest is required; "
                "construct BloodHoundImporter with a validated ScopeManifest."
            )
        if not isinstance(scope_manifest, ScopeManifest):
            raise InvalidScopeManifestError(
                "ROE requirement failed: scope_manifest must be a ScopeManifest "
                f"instance, got {type(scope_manifest).__name__}."
            )
        if not _manifest_has_any_scope(scope_manifest):
            raise InvalidScopeManifestError(
                "ROE requirement failed: scope_manifest must declare at least one "
                "of domains, ip_ranges, urls, or authorized_seeds."
            )

        self.scope_manifest = scope_manifest
        self.audit_logger = audit_logger or self._build_default_logger()

    # ------------------------------------------------------------------ api
    def import_zip(self, zip_path: Path, engagement_id: str) -> ImportResult:
        """Import a BloodHound export zip under an engagement's ROE.

        Order of operations (must not be reordered):

        1. Validate ``engagement_id`` -- raises before any audit write.
        2. Emit ``import_started`` audit entry.
        3. Iterate zip members, parse each supported JSON envelope, emit
           one ``entity_imported`` audit entry per entity type.
        4. Emit ``import_completed`` on success, or ``import_failed`` on
           any exception raised during the read/parse loop.

        Args:
            zip_path: Path to a BloodHound ``.zip`` export.
            engagement_id: Non-empty engagement identifier.

        Returns:
            :class:`ImportResult` describing the outcome. ``success`` is
            ``False`` when the read/parse loop raised; the exception's
            message lands in ``error``.

        Raises:
            MissingEngagementIdError: ``engagement_id`` is missing/empty.
        """
        self._validate_engagement_id(engagement_id)
        correlation_id = str(uuid.uuid4())
        zip_path_str = str(zip_path)
        start_time = time.monotonic()

        # AUDIT FIRST -- before opening the zip so the trail exists even
        # if the zip read itself panics.
        self._emit_event(
            event_name="import_started",
            engagement_id=engagement_id,
            correlation_id=correlation_id,
            params={
                "zip_path": zip_path_str,
                "timestamp_utc": time.time(),
                "roe_id": self.scope_manifest.roe_id,
            },
            success=True,
        )

        entities_by_type: dict[str, int] = {}
        try:
            entities_by_type = self._import_zip_members(
                zip_path=zip_path,
                engagement_id=engagement_id,
                correlation_id=correlation_id,
            )
        except Exception as exc:  # noqa: BLE001 -- funnel to audit + result
            duration = time.monotonic() - start_time
            self._emit_event(
                event_name="import_failed",
                engagement_id=engagement_id,
                correlation_id=correlation_id,
                params={
                    "zip_path": zip_path_str,
                    "error_message": str(exc),
                    "duration_seconds": duration,
                },
                success=False,
                error_detail=f"{type(exc).__name__}: {exc}",
            )
            _LOG.warning(
                "BloodHoundImporter: import failed engagement=%s zip=%s error=%s",
                engagement_id,
                zip_path_str,
                exc,
            )
            return ImportResult(
                success=False,
                engagement_id=engagement_id,
                zip_path=zip_path_str,
                total_entities=sum(entities_by_type.values()),
                entities_by_type=dict(entities_by_type),
                duration_seconds=duration,
                error=str(exc),
            )

        duration = time.monotonic() - start_time
        total = sum(entities_by_type.values())
        self._emit_event(
            event_name="import_completed",
            engagement_id=engagement_id,
            correlation_id=correlation_id,
            params={
                "zip_path": zip_path_str,
                "total_entities": total,
                "entities_by_type": dict(entities_by_type),
                "duration_seconds": duration,
            },
            success=True,
        )
        return ImportResult(
            success=True,
            engagement_id=engagement_id,
            zip_path=zip_path_str,
            total_entities=total,
            entities_by_type=dict(entities_by_type),
            duration_seconds=duration,
            error=None,
        )

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _validate_engagement_id(engagement_id: Any) -> None:
        if engagement_id is None:
            raise MissingEngagementIdError(
                "ROE requirement failed: engagement_id is required; got None."
            )
        if not isinstance(engagement_id, str):
            raise MissingEngagementIdError(
                "ROE requirement failed: engagement_id must be a string, "
                f"got {type(engagement_id).__name__}."
            )
        if not engagement_id.strip():
            raise MissingEngagementIdError(
                "ROE requirement failed: engagement_id must be a non-empty string."
            )

    def _import_zip_members(
        self,
        zip_path: Path,
        engagement_id: str,
        correlation_id: str,
    ) -> dict[str, int]:
        """Read every supported JSON member and count entities per type.

        Emits one ``entity_imported`` audit entry per (entity_type, count)
        pair. Any per-file parse error is fatal so the caller can log a
        single ``import_failed`` entry with the offending file name.
        """
        entities_by_type: dict[str, int] = {}
        with zipfile.ZipFile(zip_path, "r") as archive:
            for member in archive.namelist():
                if not member.lower().endswith(".json"):
                    continue
                entity_type = _entity_type_from_filename(member)
                with archive.open(member, "r") as fh:
                    raw = fh.read()
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        f"failed to parse BloodHound member {member!r}: {exc}"
                    ) from exc

                count = _count_entities(payload)
                entities_by_type[entity_type] = entities_by_type.get(entity_type, 0) + count
                self._emit_event(
                    event_name="entity_imported",
                    engagement_id=engagement_id,
                    correlation_id=correlation_id,
                    params={
                        "entity_type": entity_type,
                        "count": count,
                        "source_member": member,
                    },
                    success=True,
                )
        return entities_by_type

    # ---------------------------------------------------------- audit sink
    def _emit_event(
        self,
        *,
        event_name: str,
        engagement_id: str,
        correlation_id: str,
        params: dict[str, Any],
        success: bool,
        error_detail: str | None = None,
    ) -> None:
        event_type = _AUDIT_EVENT_TYPES.get(event_name, AuditEventType.TOOL_INVOCATION)
        payload: dict[str, Any] = {"engagement_id": engagement_id, "event": event_name}
        payload.update(params)
        entry = AuditEntry(
            correlation_id=correlation_id,
            event_type=event_type,
            tool_name=_TOOL_NAME,
            input_params=payload,
            output_summary=f"{event_name}: engagement={engagement_id}",
            success=success,
            error_detail=error_detail,
        )
        _run_sync(self.audit_logger.log(entry))

    @staticmethod
    def _build_default_logger() -> "AuditLogger":
        # Lazy import so this module stays importable when the logger's
        # optional dependencies are absent.
        from forge.audit.logger import AuditLogger  # noqa: PLC0415

        return AuditLogger(log_path=None)


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


# Mapping of the four audit event names to the closest existing
# AuditEventType. TOOL_INVOCATION is the neutral "the importer did work"
# category; ERROR carries the failure trail.
_AUDIT_EVENT_TYPES: dict[str, AuditEventType] = {
    "import_started": AuditEventType.TOOL_INVOCATION,
    "entity_imported": AuditEventType.TOOL_INVOCATION,
    "import_completed": AuditEventType.TOOL_INVOCATION,
    "import_failed": AuditEventType.ERROR,
}


def _entity_type_from_filename(member: str) -> str:
    """Return the entity type encoded in a BloodHound zip member name.

    BloodHound exports use flat filenames such as ``users.json`` or
    ``20240101120000_bloodhound_users.json``. We normalise by taking the
    filename stem and stripping timestamp/tool prefixes so
    ``entities_by_type`` keys stay stable across export tool versions.
    """
    stem = Path(member).stem.lower()
    # Common prefixes emitted by SharpHound/AzureHound wrappers.
    for prefix in ("bloodhound_", "sharphound_", "azurehound_"):
        if stem.startswith(prefix):
            stem = stem[len(prefix):]
    # If the stem is a timestamp+underscore+type, take the trailing token.
    if "_" in stem:
        head, _, tail = stem.rpartition("_")
        if head and tail and head.replace("-", "").isdigit():
            stem = tail
    return stem or "unknown"


def _count_entities(payload: Any) -> int:
    """Return the entity count reported by a BloodHound JSON payload.

    Preference order:

    1. ``payload["meta"]["count"]`` when it is a non-negative int.
    2. ``len(payload["data"])`` when ``data`` is a list.
    3. ``len(payload)`` when the top level is a list.
    4. ``0`` otherwise.
    """
    if isinstance(payload, dict):
        meta = payload.get("meta")
        if isinstance(meta, dict):
            reported = meta.get("count")
            if isinstance(reported, int) and reported >= 0:
                return reported
        data = payload.get("data")
        if isinstance(data, list):
            return len(data)
        return 0
    if isinstance(payload, list):
        return len(payload)
    return 0


def _run_sync(coro: Any) -> None:
    """Run an async coroutine from sync code without deadlocking.

    Mirrors :meth:`forge.governance.scope_gate.ScopeGate._emit_decision`:
    if a loop is already running we schedule the task and hand the caller
    back a strong reference through the loop; otherwise we run it to
    completion on a fresh loop.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(coro)
        return
    # Inside a running loop -- schedule and keep a strong ref via the loop.
    task = loop.create_task(coro)
    _PENDING_AUDIT_TASKS.add(task)
    task.add_done_callback(_PENDING_AUDIT_TASKS.discard)


_PENDING_AUDIT_TASKS: set[asyncio.Task[None]] = set()


# Surface pydantic ValidationError as InvalidScopeManifestError for
# callers that build a manifest from untrusted JSON.
def build_scope_manifest(data: dict[str, Any]) -> ScopeManifest:
    """Convenience helper: parse a dict into a validated ScopeManifest.

    Raises:
        InvalidScopeManifestError: The dict failed ROE validation. The
            underlying :class:`pydantic.ValidationError` is chained.
    """
    try:
        return ScopeManifest(**data)
    except ValidationError as exc:
        raise InvalidScopeManifestError(
            f"ROE requirement failed: scope_manifest is invalid: {exc}"
        ) from exc


__all__.append("build_scope_manifest")
