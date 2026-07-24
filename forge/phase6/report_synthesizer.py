"""
forge/phase6/report_synthesizer.py

Phase 6 — LLM-Assisted Report Synthesis.

Primary backends: env-configured provider cascade (`provider=auto`),
approved individual providers, or local Qwen2.5-1.5B Q4_K_M via
llama-cpp-python.
Role:  Post-engagement narrative generation only. Never called during live
       engagements. All structured data is rule-derived; the LLM handles
       narrative cohesion and executive prose only.

Architecture:
  ReportSynthesizer           — top-level orchestrator; owns the Llama instance
  ContextBuilder              — queries engagement DB → ReportContext
  PromptAssembler             — renders Jinja2 prompt template
  _derive_overall_risk()      — rule-based risk roll-up (never LLM-derived)

OPSEC invariants:
  - All outbound provider usage is explicit and confined to the reporting step.
  - Raw credential plaintext NEVER injected into the prompt.
  - SHA-256 hashes only for any credential references in context.
  - Prompt token budget enforced; overflow raises PromptOverflowError.
  - Generated report written to output_dir; never stdout-dumped.
  - Operator must confirm before report is written to disk.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import sys
import time
import csv
import tempfile
from textwrap import TextWrapper
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

import questionary
from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateNotFound

from forge.core.errors import ProviderUnavailableError
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.utils.cloud_exposure_gate import (
    is_deterministic_cloud_exposure,
    is_reportable_cloud_validation,
    latest_cloud_validation_reportability_index,
)
from forge.utils.validation_summary import safe_validation_summary as _safe_validation_summary
from forge.utils.validation_proof import parse_validated_detail

try:
    from llama_cpp import Llama  # type: ignore[import]
except ImportError:
    Llama = None

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

MODEL_FILENAME     = "qwen2.5-1.5b-instruct-q4_k_m.gguf"
DEFAULT_MODEL_DIR  = Path.home() / ".cache" / "forge" / "models"
TEMPLATE_DIR       = Path(__file__).parent / "templates"
PROMPT_TEMPLATE    = "report_prompt.j2"
REPORT_TEMPLATE    = "report_template.md"

# Token budget: 1.5B context window is 4096; reserve 512 for completion.
MAX_PROMPT_TOKENS  = 3584
MAX_COMPLETION_TOK = 2048
MAX_CORRECTION_LOOPS = 5
MIN_QUALITY_SCORE = 0.75
QUALITY_WEIGHTS = {
    "narrative_coherence": 0.25,
    "factual_accuracy": 0.35,
    "opsec_compliance": 0.25,
    "engagement_relevance": 0.15,
}

# Risk roll-up thresholds (rule-based; never LLM-derived)
RISK_THRESHOLDS = {
    "CRITICAL": 1,   # any CRITICAL vuln → CRITICAL overall
    "HIGH":     1,   # any HIGH vuln → HIGH overall (if no CRITICAL)
    "MEDIUM":   3,   # ≥3 MEDIUMs with no HIGH/CRITICAL → HIGH overall
}

MANDATORY_SECTIONS = [
    "## 1. Executive Summary",
    "## 2. Engagement Scope & Methodology",
    "## 3. Reconnaissance Findings",
    "## 4. OSINT & Credential Intelligence",
    "## 5. Vulnerability & Exposure Correlation",
    "## 6. Validation Boundaries & Evidence Handling",
    "## 7. Risk Ratings & Remediation Recommendations",
]

# Credential patterns that must never appear in a prompt or report
_CRED_LEAK_RE = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*\S+",
    re.IGNORECASE,
)
_FORBIDDEN_CONTEXT_KEYS = {
    "access_token",
    "client_secret",
    "hash_plaintext",
    "key",
    "key_enc",
    "key_raw",
    "password",
    "password_enc",
    "raw_secret",
    "raw_token",
    "refresh_token",
    "secret",
    "secret_enc",
    "token",
    "token_enc",
}
_AUTO_CASCADE_DEFAULT_ORDER = (
    "kiro_cli",
    "claude_code",
    "openai_compatible",
    "codex_cli",
    "gemini_cli",
    "bedrock_anthropic",
    "llama_cpp",
    "template",
)

# ── Exceptions ─────────────────────────────────────────────────────────────────

class ModelNotFoundError(FileNotFoundError):
    """GGUF model file absent from disk."""


class PromptOverflowError(RuntimeError):
    """Rendered prompt exceeds MAX_PROMPT_TOKENS."""


class ReportGenerationError(RuntimeError):
    """LLM returned an unusable completion."""


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class ReconContext:
    hosts:      list[dict[str, Any]] = field(default_factory=list)
    subdomains: list[str]            = field(default_factory=list)
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    archive_urls: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class OsintContext:
    emails_found:        int  = 0
    credential_hashes:   int  = 0   # count only; never plaintext
    breach_sources:      list[str] = field(default_factory=list)
    email_intelligence_records: int = 0
    intelligence_sources: list[str] = field(default_factory=list)
    account_existence_records: int = 0
    registered_account_count: int = 0
    registered_account_services: list[str] = field(default_factory=list)
    account_existence_rate_limited: int = 0
    breached_email_count: int = 0
    reputation_alert_count: int = 0
    paste_alert_count: int = 0
    key_findings_count:  int  = 0


@dataclass
class SeedSummaryContext:
    seeds: list[dict[str, Any]] = field(default_factory=list)
    type_counts: dict[str, int] = field(default_factory=dict)
    relation_count: int = 0
    relations: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ExploitContext:
    finding_count:      int  = 0
    cve_count:         int  = 0
    critical_count:    int  = 0
    high_count:        int  = 0
    medium_count:      int  = 0
    exploited:         list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PostExploitContext:
    shells_spawned:      int = 0
    persistence_count:   int = 0
    lateral_hosts:       int = 0
    data_collected_gb:   float = 0.0
    techniques:          list[str] = field(default_factory=list)
    artifact_summary:    dict[str, int] = field(default_factory=dict)
    artifact_type_summary: dict[str, dict[str, int]] = field(default_factory=dict)


@dataclass
class OngoingIntelligenceContext:
    monitoring_enabled:       bool  = False
    monitored_keywords:       list[str] = field(default_factory=list)
    monitoring_window_start:  datetime | None = None
    monitoring_window_end:    datetime | None = None
    new_findings_count:       int   = 0
    high_severity_count:      int   = 0
    new_breach_sources:       list[str] = field(default_factory=list)
    summary_narrative:        str   = ""


@dataclass
class ReportContext:
    engagement_id:       int
    engagement_name:     str
    operator:            str
    scope:               list[str]
    start_date:          str
    end_date:            str
    recon:               ReconContext
    osint:               OsintContext
    exploits:            ExploitContext
    post_exploitation:   PostExploitContext
    cloud_validation_inventory: list[dict[str, Any]] = field(default_factory=list)
    seed_summary:        SeedSummaryContext = field(default_factory=SeedSummaryContext)
    ongoing_intelligence: OngoingIntelligenceContext = field(
        default_factory=OngoingIntelligenceContext
    )
    overall_risk:        str = "UNKNOWN"


@dataclass
class ValidationTelemetry:
    quality_score: float
    correction_loops: int
    feedback_text: str
    narrative_coherence_score: float
    opsec_violation_count: int
    hallucination_score: float
    factual_accuracy_score: float
    engagement_context_relevance: float
    validator_ok: bool
    final_approval: bool


# ── Context builder ────────────────────────────────────────────────────────────

class ContextBuilder:
    """
    Queries the engagement SQLite DB and assembles a ReportContext.

    Design constraints:
      - Credential plaintexts are NEVER loaded. Only counts and SHA-256
        hashes appear in the context dict.
      - Evidence strings from vulnerability_findings are capped at 512 chars.
      - All text fields optionally cleaned by clean_context_fields() when
        --clean-text is active.
    """

    def __init__(
        self,
        db_path: Path,
        engagement_id: int,
        clean_text: bool = False,
    ) -> None:
        self._db      = db_path
        self._eid     = engagement_id
        self._clean   = clean_text

    # ------------------------------------------------------------------

    def build(self) -> ReportContext:
        con = sqlite3.connect(self._db)
        con.row_factory = sqlite3.Row
        try:
            eng  = self._load_engagement(con)
            ctx  = ReportContext(
                engagement_id       = self._eid,
                engagement_name     = eng["name"],
                operator            = self._row_get(eng, "operator", "Unknown"),
                scope               = self._load_scope(con),
                start_date          = self._row_get(eng, "start_date", ""),
                end_date            = self._row_get(eng, "end_date", ""),
                recon               = self._load_recon(con),
                osint               = self._load_osint(con),
                exploits            = self._load_exploits(con),
                post_exploitation   = self._load_post_exploit(con),
                cloud_validation_inventory=self._cloud_validation_inventory(con),
                seed_summary        = self._load_seed_summary(con),
                ongoing_intelligence= self._load_ongoing_intel(con),
            )
            ctx.overall_risk = _derive_overall_risk(ctx.exploits)
        finally:
            con.close()

        if self._clean:
            ctx = self._apply_text_cleaning(ctx)

        return ctx

    # ------------------------------------------------------------------

    def _load_engagement(self, con: sqlite3.Connection) -> sqlite3.Row:
        row = con.execute(
            "SELECT * FROM engagements WHERE id=?", (self._eid,)
        ).fetchone()
        if not row:
            raise ValueError(f"Engagement {self._eid} not found in DB.")
        return row

    @staticmethod
    def _row_get(row: sqlite3.Row, key: str, default: Any) -> Any:
        return row[key] if key in row.keys() and row[key] is not None else default

    @staticmethod
    def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
        try:
            return {
                row[1]
                for row in con.execute(f"PRAGMA table_info({table_name})").fetchall()
            }
        except sqlite3.OperationalError:
            return set()

    def _seed_email_values(self, con: sqlite3.Connection) -> list[str]:
        try:
            rows = con.execute(
                """
                SELECT DISTINCT seed_value
                FROM engagement_seeds
                WHERE engagement_id=?
                  AND seed_type='email'
                  AND COALESCE(status, 'pending') != 'failed'
                """,
                (self._eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        seen: set[str] = set()
        values: list[str] = []
        for row in rows:
            email = str(row[0] or "").strip().lower()
            if "@" not in email or email in seen:
                continue
            seen.add(email)
            values.append(email)
        return values

    def _seed_host_values(self, con: sqlite3.Connection) -> list[str]:
        try:
            rows = con.execute(
                """
                SELECT DISTINCT seed_value, source
                FROM engagement_seeds
                WHERE engagement_id=?
                  AND seed_type IN ('domain', 'subdomain')
                  AND COALESCE(status, 'pending') != 'failed'
                """,
                (self._eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        seen: set[str] = set()
        values: list[str] = []
        for row in rows:
            hostname = str(row[0] or "").strip().lower()
            source = str(row[1] or "").strip().lower()
            if source in {"scope", "operator"}:
                continue
            if not hostname or "." not in hostname or hostname in seen:
                continue
            seen.add(hostname)
            values.append(hostname)
        return values

    @staticmethod
    def _safe_seed_display_value(seed_value: str, seed_type: str) -> str:
        value = str(seed_value or "").strip()
        if seed_type in {"url", "apk_url"}:
            try:
                parsed = urlsplit(value)
            except ValueError:
                return value[:160]
            value = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        return value[:160]

    @classmethod
    def _archive_url_context_entry(cls, row: sqlite3.Row) -> dict[str, Any] | None:
        raw_metadata = str(row["tech_stack_json"] or "{}")
        try:
            metadata = json.loads(raw_metadata)
        except json.JSONDecodeError:
            metadata = {}
        if not isinstance(metadata, dict):
            metadata = {}
        discovered_from = str(metadata.get("discovered_from") or "").strip()
        archive_sources = [
            str(source or "").strip()
            for source in (metadata.get("archive_sources") or [])
            if str(source or "").strip()
        ]
        provider_sources = [
            str(source or "").strip()
            for source in (metadata.get("provider_sources") or [])
            if str(source or "").strip()
        ]
        source_set = {source.lower() for source in [*archive_sources, *provider_sources]}
        if discovered_from != "historical_cdx" and not (source_set & {"wayback", "commoncrawl"}):
            return None
        url_value = cls._safe_seed_display_value(str(row["resolved_url"] or ""), "url")
        if not url_value:
            return None
        sources = archive_sources or provider_sources or ["historical_cdx"]
        return {
            "url": url_value,
            "sources": sources[:4],
            "root_domain": str(metadata.get("root_domain") or "").strip()[:160],
            "discovered_from": discovered_from,
            "title": str(row["title"] or "").strip()[:160],
            "seen": str(row["discovered_at"] or "").strip(),
        }

    def _load_archive_urls(self, con: sqlite3.Connection) -> list[dict[str, Any]]:
        try:
            rows = con.execute(
                """
                SELECT COALESCE(final_url, url) AS resolved_url,
                       title,
                       tech_stack_json,
                       discovered_at
                FROM crawl_results
                WHERE engagement_id=?
                ORDER BY id DESC
                LIMIT 100
                """,
                (self._eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows:
            entry = self._archive_url_context_entry(row)
            if entry is None:
                continue
            key = str(entry["url"]).lower()
            if key in seen:
                continue
            seen.add(key)
            entries.append(entry)
            if len(entries) >= 25:
                break
        return entries

    @staticmethod
    def _scrub_evidence_metadata(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}

        def _scrub(current: Any) -> Any:
            if isinstance(current, dict):
                clean: dict[str, Any] = {}
                for raw_key, raw_value in current.items():
                    key = str(raw_key)
                    if key.lower() in _FORBIDDEN_CONTEXT_KEYS:
                        continue
                    clean[key] = _scrub(raw_value)
                return clean
            if isinstance(current, list):
                return [_scrub(item) for item in current]
            if current is None or isinstance(current, (str, int, float, bool)):
                return current
            return str(current)

        scrubbed = _scrub(value)
        return scrubbed if isinstance(scrubbed, dict) else {}

    @classmethod
    def _relation_evidence_summary(cls, evidence: dict[str, Any]) -> str:
        if not evidence:
            return ""
        parts: list[str] = []
        for key in ("rule", "extract_rule", "parser", "format", "artifact_type"):
            value = str(evidence.get(key) or "").strip()
            if value:
                parts.append(f"{key}={value}")
        for key in ("payload_count", "metadata_payload_count", "relationship_payload_count"):
            value = evidence.get(key)
            if value not in (None, ""):
                parts.append(f"{key}={value}")
        source_parts: list[str] = []
        for key in ("archive_sources", "provider_sources"):
            raw_sources = evidence.get(key)
            if not isinstance(raw_sources, list):
                continue
            for raw_source in raw_sources:
                source = str(raw_source or "").strip()
                if source and source not in source_parts:
                    source_parts.append(source)
        if source_parts:
            parts.append(f"sources={','.join(source_parts)}")
        root_domain = str(evidence.get("root_domain") or "").strip()
        if root_domain:
            parts.append(f"root={root_domain}")
        source_url = str(evidence.get("source_url") or "").strip()
        if source_url:
            parts.append(f"source={cls._safe_seed_display_value(source_url, 'url')}")
        source_file = str(evidence.get("source_file") or "").strip()
        if source_file and source_file != source_url:
            parts.append(f"file={cls._safe_seed_display_value(source_file, 'url')}")
        if not parts:
            for key in ("service", "ref", "source"):
                value = str(evidence.get(key) or "").strip()
                if value:
                    parts.append(f"{key}={value}")
        return " ".join(parts)[:240]

    @staticmethod
    def _cloud_seed_refs(seed_value: str) -> list[tuple[str, str]]:
        value = str(seed_value or "").strip()
        if not value:
            return []
        refs: list[tuple[str, str]] = []
        lowered = value.lower()

        s3_match = re.search(r"\bs3://([a-z0-9.\-]{3,63})(?:/|$)", lowered)
        if s3_match:
            refs.append(("aws_s3", s3_match.group(1)))
        gcs_uri_match = re.search(r"\bgs://([a-z0-9._\-]{3,222})(?:/|$)", lowered)
        if gcs_uri_match:
            refs.append(("gcs", gcs_uri_match.group(1)))

        try:
            parsed = urlsplit(value if "://" in value else f"https://{value}")
        except ValueError:
            parsed = None
        host = (parsed.hostname or "").lower() if parsed else ""
        path = (parsed.path or "").strip("/") if parsed else ""
        if host:
            if host.endswith(".firebaseio.com"):
                refs.append(("firebase", host.removesuffix(".firebaseio.com")))
            elif host.endswith(".firebaseapp.com"):
                refs.append(("firebase", host.removesuffix(".firebaseapp.com")))
            elif host.endswith(".web.app"):
                refs.append(("firebase", host.removesuffix(".web.app")))
            elif host.endswith(".supabase.co"):
                refs.append(("supabase", host.removesuffix(".supabase.co")))
            elif host.endswith(".s3.amazonaws.com"):
                refs.append(("aws_s3", host.removesuffix(".s3.amazonaws.com")))
            elif host == "s3.amazonaws.com" and path:
                refs.append(("aws_s3", path.split("/", 1)[0].lower()))
            elif host.endswith(".storage.googleapis.com"):
                refs.append(("gcs", host.removesuffix(".storage.googleapis.com")))
            elif host in {"storage.googleapis.com", "storage.cloud.google.com"} and path:
                refs.append(("gcs", path.split("/", 1)[0].lower()))
            elif host.endswith(".digitaloceanspaces.com"):
                prefix = host.removesuffix(".digitaloceanspaces.com")
                parts = prefix.split(".")
                if len(parts) >= 2:
                    bucket = ".".join(parts[:-1]).strip(".")
                    region = parts[-1].strip(".")
                    if bucket and region:
                        refs.append(("do_spaces", f"{region}/{bucket}"))
                elif path:
                    bucket = path.split("/", 1)[0].lower()
                    region = prefix.strip(".")
                    if bucket and region:
                        refs.append(("do_spaces", f"{region}/{bucket}"))
            elif host.endswith(".web.core.windows.net"):
                account = host.split(".", 1)[0]
                if account:
                    refs.append(("azure_blob", f"{account}/$web"))
            elif host.endswith((".blob.core.windows.net", ".dfs.core.windows.net")) and path:
                account = host.split(".", 1)[0]
                container = path.split("/", 1)[0].lower()
                if account and container:
                    refs.append(("azure_blob", f"{account}/{container}"))

        seen: set[tuple[str, str]] = set()
        ordered: list[tuple[str, str]] = []
        for asset_type, identifier in refs:
            normalized = (asset_type, identifier.strip().lower())
            if not normalized[1] or normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(normalized)
        return ordered

    def _cloud_validation_index(self, con: sqlite3.Connection) -> dict[tuple[str, str], str]:
        return {
            key: "VALIDATED" if reportable else ""
            for key, reportable in latest_cloud_validation_reportability_index(
                con,
                self._eid,
                require_stable_proof=True,
            ).items()
        }

    @staticmethod
    def _normalize_validation_asset_type(value: str) -> str:
        normalized = str(value or "").strip().lower()
        if normalized == "s3":
            return "aws_s3"
        if normalized == "digitalocean_spaces":
            return "do_spaces"
        if normalized == "google_cloud_storage":
            return "gcs"
        if normalized == "azure_blob_storage":
            return "azure_blob"
        return normalized

    @staticmethod
    def _validation_asset_types_for_provider(provider: str) -> list[str]:
        normalized = str(provider or "").strip().lower()
        return {
            "aws": ["aws_s3"],
            "amazon": ["aws_s3"],
            "digitalocean": ["do_spaces"],
            "gcp": ["gcs"],
            "google": ["gcs"],
            "azure": ["azure_blob"],
            "firebase": ["firebase"],
            "supabase": ["supabase"],
        }.get(normalized, [])

    def _cloud_validation_metadata_index(
        self,
        con: sqlite3.Connection,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        columns = self._table_columns(con, "cloud_validation_results")
        if not {"asset_type", "identifier", "validation_status"}.issubset(columns):
            return {}
        select_parts = [
            "asset_type",
            "identifier",
            "provider_identifier" if "provider_identifier" in columns else "identifier AS provider_identifier",
            "validation_status",
            "validation_method" if "validation_method" in columns else "NULL AS validation_method",
            "http_status" if "http_status" in columns else "NULL AS http_status",
            "notes" if "notes" in columns else "NULL AS notes",
            "evidence" if "evidence" in columns else "NULL AS evidence",
            "checked_at" if "checked_at" in columns else "NULL AS checked_at",
        ]
        order_checked_at_expr = "COALESCE(checked_at, '')" if "checked_at" in columns else "''"
        order_id_expr = "id" if "id" in columns else "0"
        try:
            rows = con.execute(
                f"SELECT {', '.join(select_parts)} FROM cloud_validation_results "
                "WHERE engagement_id=? "
                f"ORDER BY asset_type ASC, identifier ASC, {order_checked_at_expr} ASC, "
                f"{order_id_expr} ASC",
                (self._eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            return {}

        metadata: dict[tuple[str, str], dict[str, Any]] = {}
        for row in rows:
            asset_type = self._normalize_validation_asset_type(str(row["asset_type"] or ""))
            identifier = str(row["identifier"] or "").strip().lower()
            if not asset_type or not identifier:
                continue
            metadata[(asset_type, identifier)] = {
                "validation_asset_type": asset_type,
                "provider_identifier": str(row["provider_identifier"] or row["identifier"] or "").strip(),
                "validation_status": str(row["validation_status"] or "").strip().upper(),
                "validation_method": str(row["validation_method"] or "").strip(),
                "validation_http_status": row["http_status"],
                "validation_notes": _safe_validation_summary(row["notes"]),
                "validation_evidence_summary": _safe_validation_summary(row["evidence"]),
                "validation_checked_at": str(row["checked_at"] or "").strip(),
            }
        return metadata

    def _cloud_validation_inventory(self, con: sqlite3.Connection) -> list[dict[str, Any]]:
        metadata = self._cloud_validation_metadata_index(con)
        inventory = [
            {
                "asset_type": asset_type,
                "identifier": identifier,
                "provider_identifier": str(item.get("provider_identifier") or identifier),
                "validation_status": str(item.get("validation_status") or ""),
                "method": str(item.get("validation_method") or ""),
                "http_status": item.get("validation_http_status"),
                "checked_at": str(item.get("validation_checked_at") or ""),
                "notes": str(item.get("validation_notes") or ""),
                "evidence_summary": str(item.get("validation_evidence_summary") or ""),
            }
            for (asset_type, identifier), item in metadata.items()
        ]
        inventory.sort(key=lambda item: (str(item["asset_type"]), str(item["identifier"])))
        return inventory

    def _finding_validation_candidates(self, row: sqlite3.Row) -> list[tuple[str, str]]:
        asset_types: list[str] = []
        identifiers: list[str] = []

        def _add_asset_type(value: str) -> None:
            normalized = self._normalize_validation_asset_type(value)
            if normalized and normalized not in asset_types:
                asset_types.append(normalized)

        def _add_identifier(value: str) -> None:
            normalized = str(value or "").strip().lower()
            if normalized and normalized not in identifiers:
                identifiers.append(normalized)

        parameter = str(row["parameter"] or "").strip() if "parameter" in row.keys() else ""
        if parameter:
            _add_asset_type(parameter.split(":", 1)[0])

        cloud_provider = str(row["cloud_provider"] or "").strip() if "cloud_provider" in row.keys() else ""
        for asset_type in self._validation_asset_types_for_provider(cloud_provider):
            _add_asset_type(asset_type)

        resource_id = str(row["resource_id"] or "").strip() if "resource_id" in row.keys() else ""
        if resource_id:
            _add_identifier(resource_id)

        target_url = str(row["target_url"] or "").strip() if "target_url" in row.keys() else ""
        if target_url:
            try:
                parsed = urlsplit(target_url)
            except ValueError:
                parsed = None
            if parsed and parsed.scheme:
                scheme_asset = self._normalize_validation_asset_type(parsed.scheme)
                if scheme_asset:
                    _add_asset_type(scheme_asset)
                    parsed_identifier = (parsed.netloc + "/" + parsed.path.strip("/")).strip("/")
                    if parsed_identifier:
                        _add_identifier(parsed_identifier)
            elif target_url:
                _add_identifier(target_url)

        candidates: list[tuple[str, str]] = []
        for asset_type in asset_types:
            for identifier in identifiers:
                candidate = (asset_type, identifier)
                if candidate not in candidates:
                    candidates.append(candidate)
        return candidates

    def _finding_validation_metadata(
        self,
        row: sqlite3.Row,
        validation_index: dict[tuple[str, str], dict[str, Any]],
    ) -> dict[str, Any]:
        empty = {
            "validation_status": "",
            "validation_method": "",
            "validation_http_status": None,
            "validation_notes": "",
            "validation_evidence_summary": "",
            "validation_checked_at": "",
        }
        for candidate in self._finding_validation_candidates(row):
            metadata = validation_index.get(candidate)
            if metadata:
                return {**empty, **metadata}
        return empty

    @staticmethod
    def _finding_key_validation_metadata(evidence: str) -> dict[str, Any]:
        proof = parse_validated_detail(evidence)
        if not proof["validation_method"]:
            return {
                "validation_status": "",
                "validation_method": "",
                "validation_http_status": None,
                "validation_notes": "",
                "validation_evidence_summary": "",
                "validation_checked_at": "",
            }
        return {
            "validation_status": proof["validation_status"],
            "validation_method": proof["validation_method"],
            "validation_http_status": None,
            "validation_notes": proof["validation_proof"],
            "validation_evidence_summary": "",
            "validation_checked_at": "",
        }

    def _seed_allowed_in_report(
        self,
        *,
        seed_value: str,
        source: str,
        validation_index: dict[tuple[str, str], str],
    ) -> bool:
        if source in {"operator", "scope"}:
            return True
        cloud_refs = self._cloud_seed_refs(seed_value)
        raw_identifier = str(seed_value or "").strip().lower()
        direct_statuses = [
            status
            for (_asset_type, identifier), status in validation_index.items()
            if identifier == raw_identifier
        ]
        if not cloud_refs and not direct_statuses:
            return True
        return any(validation_index.get(ref) == "VALIDATED" for ref in cloud_refs) or any(
            status == "VALIDATED" for status in direct_statuses
        )

    def _load_seed_summary(self, con: sqlite3.Connection) -> SeedSummaryContext:
        try:
            rows = con.execute(
                """
                SELECT id, seed_value, seed_type, source, status, depth, confidence
                FROM engagement_seeds
                WHERE engagement_id=?
                  AND COALESCE(status, 'pending') != 'failed'
                ORDER BY depth ASC, seed_type ASC, seed_value ASC
                LIMIT 250
                """,
                (self._eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            return SeedSummaryContext()

        seeds: list[dict[str, Any]] = []
        type_counts: dict[str, int] = {}
        seen: set[tuple[str, str]] = set()
        validation_index = self._cloud_validation_index(con)
        for row in rows:
            seed_type = str(row["seed_type"] or "other").strip().lower()
            source = str(row["source"] or "").strip().lower()
            raw_value = str(row["seed_value"] or "")
            if not self._seed_allowed_in_report(
                seed_value=raw_value,
                source=source,
                validation_index=validation_index,
            ):
                continue
            display_value = self._safe_seed_display_value(str(row["seed_value"] or ""), seed_type)
            key = (seed_type, display_value.lower())
            if not display_value or key in seen:
                continue
            seen.add(key)
            type_counts[seed_type] = type_counts.get(seed_type, 0) + 1
            seeds.append(
                {
                    "id": int(row["id"]),
                    "value": display_value,
                    "type": seed_type,
                    "source": source,
                    "status": str(row["status"] or ""),
                    "depth": int(row["depth"] or 0),
                    "confidence": round(float(row["confidence"] or 0.0), 2),
                }
            )

        try:
            relation_count = int(
                con.execute(
                    "SELECT COUNT(*) FROM seed_relations WHERE engagement_id=?",
                    (self._eid,),
                ).fetchone()[0]
            )
        except sqlite3.OperationalError:
            relation_count = 0

        relations: list[dict[str, Any]] = []
        if relation_count:
            relation_columns = self._table_columns(con, "seed_relations")
            evidence_select = (
                "sr.evidence_json AS evidence_json"
                if "evidence_json" in relation_columns
                else "NULL AS evidence_json"
            )
            try:
                relation_rows = con.execute(
                    f"""
                    SELECT src.seed_value AS source_value,
                           src.seed_type AS source_type,
                           src.source AS source_seed_origin,
                           tgt.seed_value AS target_value,
                           tgt.seed_type AS target_type,
                           tgt.source AS target_seed_origin,
                           sr.relation_type,
                           sr.confidence,
                           {evidence_select}
                    FROM seed_relations sr
                    JOIN engagement_seeds src ON src.id=sr.source_seed_id
                    JOIN engagement_seeds tgt ON tgt.id=sr.target_seed_id
                    WHERE sr.engagement_id=?
                    ORDER BY sr.confidence DESC, sr.id ASC
                    LIMIT 50
                    """,
                    (self._eid,),
                ).fetchall()
            except sqlite3.OperationalError:
                relation_rows = []
            for row in relation_rows:
                source_type = str(row["source_type"] or "other").strip().lower()
                target_type = str(row["target_type"] or "other").strip().lower()
                source_value_raw = str(row["source_value"] or "")
                target_value_raw = str(row["target_value"] or "")
                if not self._seed_allowed_in_report(
                    seed_value=source_value_raw,
                    source=str(row["source_seed_origin"] or "").strip().lower(),
                    validation_index=validation_index,
                ):
                    continue
                if not self._seed_allowed_in_report(
                    seed_value=target_value_raw,
                    source=str(row["target_seed_origin"] or "").strip().lower(),
                    validation_index=validation_index,
                ):
                    continue
                evidence_metadata: dict[str, Any] = {}
                if row["evidence_json"]:
                    try:
                        parsed_evidence = json.loads(str(row["evidence_json"]))
                    except json.JSONDecodeError:
                        parsed_evidence = {}
                    evidence_metadata = self._scrub_evidence_metadata(parsed_evidence)
                relations.append(
                    {
                        "source_type": source_type,
                        "source_value": self._safe_seed_display_value(source_value_raw, source_type),
                        "target_type": target_type,
                        "target_value": self._safe_seed_display_value(target_value_raw, target_type),
                        "relation_type": str(row["relation_type"] or "related_asset"),
                        "confidence": round(float(row["confidence"] or 0.0), 2),
                        "evidence": self._relation_evidence_summary(evidence_metadata),
                        "evidence_metadata": evidence_metadata,
                    }
                )

        return SeedSummaryContext(
            seeds=seeds,
            type_counts=dict(sorted(type_counts.items())),
            relation_count=relation_count,
            relations=relations,
        )

    def _load_scope(self, con: sqlite3.Connection) -> list[str]:
        try:
            rows = con.execute(
                "SELECT scope_entry FROM engagement_scope WHERE engagement_id=?",
                (self._eid,),
            ).fetchall()
            return [r["scope_entry"] for r in rows]
        except sqlite3.OperationalError:
            if "scope_json" not in self._table_columns(con, "engagements"):
                return []
            row = con.execute(
                "SELECT scope_json FROM engagements WHERE id=?",
                (self._eid,),
            ).fetchone()
            if not row or not row["scope_json"]:
                return []
            try:
                return json.loads(row["scope_json"])
            except json.JSONDecodeError:
                return []

    def _load_recon(self, con: sqlite3.Connection) -> ReconContext:
        try:
            hosts = con.execute(
                "SELECT hostname, ip_address, os_guess FROM hosts WHERE engagement_id=?",
                (self._eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            try:
                hosts = con.execute(
                    "SELECT hostname, ip AS ip_address, os_family AS os_guess "
                    "FROM hosts WHERE engagement_id=?",
                    (self._eid,),
                ).fetchall()
            except sqlite3.OperationalError:
                hosts = []
        try:
            subs = con.execute(
                "SELECT fqdn FROM subdomains WHERE engagement_id=?",
                (self._eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            subs = []
        seed_hosts = self._seed_host_values(con)
        hostnames_seen = {
            str(r["hostname"] or "").strip().lower()
            for r in hosts
            if str(r["hostname"] or "").strip()
        }
        for hostname in seed_hosts:
            if hostname not in hostnames_seen:
                hosts.append({"hostname": hostname, "ip_address": "", "os_guess": ""})
                hostnames_seen.add(hostname)
        # Fallback (2026-07-07): historical schemas never populated a
        # dedicated subdomains table — the subdomain_enum module writes
        # hostname strings into ``hosts.hostname``. Read from there when
        # the primary table is empty so Phase 6 reports don't say
        # "0 subdomains" while hosts.hostname has 11 rows.
        if not subs:
            try:
                rows = con.execute(
                    "SELECT DISTINCT hostname FROM hosts "
                    "WHERE engagement_id=? "
                    "  AND hostname IS NOT NULL "
                    "  AND hostname != '' "
                    "  AND hostname != ip",
                    (self._eid,),
                ).fetchall()
                subs = [{"fqdn": r["hostname"]} for r in rows]
            except sqlite3.OperationalError:
                subs = []
        sub_seen = {
            str(r["fqdn"] or "").strip().lower()
            for r in subs
            if str(r["fqdn"] or "").strip()
        }
        for hostname in seed_hosts:
            if hostname not in sub_seen:
                subs.append({"fqdn": hostname})
                sub_seen.add(hostname)
        try:
            ports = con.execute(
                "SELECT ip_address, port, service FROM open_ports WHERE engagement_id=?",
                (self._eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            try:
                ports = con.execute(
                    "SELECT h.ip AS ip_address, s.port, s.service_name AS service "
                    "FROM services s JOIN hosts h ON h.id=s.host_id WHERE h.engagement_id=?",
                    (self._eid,),
                ).fetchall()
            except sqlite3.OperationalError:
                ports = []
        return ReconContext(
            hosts      = [dict(r) for r in hosts],
            subdomains = [r["fqdn"] for r in subs],
            open_ports = [dict(r) for r in ports],
            archive_urls = self._load_archive_urls(con),
        )

    def _load_osint(self, con: sqlite3.Connection) -> OsintContext:
        try:
            email_rows = con.execute(
                "SELECT DISTINCT email FROM emails WHERE engagement_id=?", (self._eid,)
            ).fetchall()
        except sqlite3.OperationalError:
            email_rows = []
        email_values = {
            str(row[0]).strip().lower()
            for row in email_rows
            if row[0] and "@" in str(row[0])
        }
        email_values.update(self._seed_email_values(con))
        email_count = len(email_values)
        try:
            hash_count = con.execute(
                "SELECT COUNT(*) FROM credential_hashes WHERE engagement_id=?",
                (self._eid,),
            ).fetchone()[0]
            breach_rows = con.execute(
                "SELECT DISTINCT source FROM credential_hashes WHERE engagement_id=?",
                (self._eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            try:
                hash_count = con.execute(
                    "SELECT COUNT(*) FROM credentials WHERE engagement_id=? "
                    "AND (hash_type IS NOT NULL OR password_hash IS NOT NULL)",
                    (self._eid,),
                ).fetchone()[0]
                breach_rows = con.execute(
                    "SELECT DISTINCT source FROM credentials WHERE engagement_id=? "
                    "AND source IS NOT NULL",
                    (self._eid,),
                ).fetchall()
            except sqlite3.OperationalError:
                hash_count = 0
                breach_rows = []
        intel_rows = []
        if self._table_columns(con, "email_intelligence"):
            intel_columns = self._table_columns(con, "email_intelligence")
            paste_expr = "paste_count" if "paste_count" in intel_columns else "0 AS paste_count"
            try:
                intel_rows = con.execute(
                    f"""
                    SELECT email, source, breach_count, {paste_expr}
                    FROM email_intelligence
                    WHERE engagement_id=?
                    """,
                    (self._eid,),
                ).fetchall()
            except sqlite3.OperationalError:
                intel_rows = []
        breach_sources = {
            str(row[0] or "").strip()
            for row in breach_rows
            if str(row[0] or "").strip()
        }
        intelligence_sources = sorted(
            {
                str(row["source"] or "").strip()
                for row in intel_rows
                if str(row["source"] or "").strip()
            }
        )
        account_rows = []
        account_columns = self._table_columns(con, "account_existence")
        if account_columns and {"email", "service"}.issubset(account_columns):
            exists_expr = "exists_flag" if "exists_flag" in account_columns else "1 AS exists_flag"
            rate_limited_expr = "rate_limited" if "rate_limited" in account_columns else "0 AS rate_limited"
            source_tool_expr = "source_tool" if "source_tool" in account_columns else "'holehe' AS source_tool"
            try:
                account_rows = con.execute(
                    f"""
                    SELECT email, service, {exists_expr}, {rate_limited_expr}, {source_tool_expr}
                    FROM account_existence
                    WHERE engagement_id=?
                    """,
                    (self._eid,),
                ).fetchall()
            except sqlite3.OperationalError:
                account_rows = []
        if account_rows:
            intelligence_sources = sorted(
                set(intelligence_sources)
                | {
                    str(row["source_tool"] or "").strip()
                    for row in account_rows
                    if str(row["source_tool"] or "").strip()
                }
            )
        registered_account_services = sorted(
            {
                str(row["service"] or "").strip()
                for row in account_rows
                if int(row["exists_flag"] or 0) == 1 and str(row["service"] or "").strip()
            }
        )
        registered_account_count = sum(1 for row in account_rows if int(row["exists_flag"] or 0) == 1)
        account_existence_rate_limited = sum(1 for row in account_rows if int(row["rate_limited"] or 0) == 1)
        breached_emails: set[str] = set()
        reputation_alerts: set[str] = set()
        paste_alerts: set[str] = set()
        for row in intel_rows:
            email = str(row["email"] or "").strip().lower()
            source = str(row["source"] or "").strip()
            source_key = source.lower()
            breach_count = int(row["breach_count"] or 0)
            paste_count = int(row["paste_count"] or 0)
            if paste_count > 0 and email:
                paste_alerts.add(email)
            if source_key == "emailrep":
                if breach_count > 0 and email:
                    reputation_alerts.add(email)
                continue
            if (breach_count > 0 or paste_count > 0) and email:
                breached_emails.add(email)
            if (breach_count > 0 or paste_count > 0) and source:
                breach_sources.add(source)
        try:
            key_count = self._reportable_key_findings_count(con)
        except sqlite3.OperationalError:
            key_count = 0
        return OsintContext(
            emails_found       = email_count,
            credential_hashes  = hash_count,
            breach_sources     = sorted(breach_sources),
            email_intelligence_records = len(intel_rows),
            intelligence_sources = intelligence_sources,
            account_existence_records = len(account_rows),
            registered_account_count = registered_account_count,
            registered_account_services = registered_account_services,
            account_existence_rate_limited = account_existence_rate_limited,
            breached_email_count = len(breached_emails),
            reputation_alert_count = len(reputation_alerts),
            paste_alert_count = len(paste_alerts),
            key_findings_count = key_count,
        )

    def _reportable_key_findings_count(self, con: sqlite3.Connection) -> int:
        columns = self._table_columns(con, "key_scanner_findings")
        if not {"engagement_id", "validation_state"}.issubset(columns):
            return 0
        select_parts = [
            "validation_state",
            "service" if "service" in columns else "NULL AS service",
            "domain" if "domain" in columns else "NULL AS domain",
            "validation_detail" if "validation_detail" in columns else "NULL AS validation_detail",
        ]
        rows = con.execute(
            f"""
            SELECT {', '.join(select_parts)}
            FROM key_scanner_findings
            WHERE engagement_id=? AND validation_state='ACTIVE'
            """,
            (self._eid,),
        ).fetchall()
        validation_index = self._cloud_validation_index(con)
        return sum(1 for row in rows if self._key_row_allowed_in_report(row, validation_index))

    def _key_row_allowed_in_report(
        self,
        row: sqlite3.Row,
        validation_index: dict[tuple[str, str], str],
    ) -> bool:
        proof = parse_validated_detail(row["validation_detail"])
        if proof["validation_status"] == "VALIDATED":
            return True
        service = self._normalize_validation_asset_type(str(row["service"] or ""))
        identifier = str(row["domain"] or "").strip().lower()
        if not service or not identifier:
            return False
        direct = validation_index.get((service, identifier)) == "VALIDATED"
        linked = any(
            validation_index.get((asset_type, identifier)) == "VALIDATED"
            for asset_type in self._validation_asset_types_for_provider(service)
        )
        return direct or linked

    def _load_exploits(self, con: sqlite3.Connection) -> ExploitContext:
        columns = self._table_columns(con, "vulnerability_findings")
        if not columns:
            rows = []
        else:
            select_parts = [
                "severity" if "severity" in columns else "NULL AS severity",
                "vuln_type" if "vuln_type" in columns else "NULL AS vuln_type",
                "cve_id" if "cve_id" in columns else "NULL AS cve_id",
                "title" if "title" in columns else "NULL AS title",
                "evidence" if "evidence" in columns else "NULL AS evidence",
                "target_url" if "target_url" in columns else "NULL AS target_url",
                "parameter" if "parameter" in columns else "NULL AS parameter",
                "description" if "description" in columns else "NULL AS description",
                "cloud_provider" if "cloud_provider" in columns else "NULL AS cloud_provider",
                "resource_id" if "resource_id" in columns else "NULL AS resource_id",
                "remediation_cli" if "remediation_cli" in columns else "NULL AS remediation_cli",
            ]
            try:
                rows = con.execute(
                    f"SELECT {', '.join(select_parts)} FROM vulnerability_findings "
                    "WHERE engagement_id=?",
                    (self._eid,),
                ).fetchall()
            except sqlite3.OperationalError:
                rows = []
        exploited = []
        validation_metadata = self._cloud_validation_metadata_index(con)
        for r in rows:
            evidence = (r["evidence"] or "")[:512]   # V-09: evidence capped at 512 chars
            finding = {
                "vuln_type": r["vuln_type"],
                "cve_id":   r["cve_id"],
                "severity": r["severity"],
                "title":    r["title"],
                "evidence": evidence,
                "target_url": r["target_url"],
                "parameter": r["parameter"],
                "description": r["description"],
                "cloud_provider": r["cloud_provider"],
                "resource_id": r["resource_id"],
                "remediation_cli": r["remediation_cli"],
            }
            structured_validation = self._finding_validation_metadata(r, validation_metadata)
            if not structured_validation.get("validation_method"):
                structured_validation = {
                    **structured_validation,
                    **self._finding_key_validation_metadata(evidence),
                }
            finding.update(structured_validation)
            if self._finding_is_unvalidated_key_exposure(finding):
                continue
            if self._finding_is_unvalidated_deterministic_cloud_exposure(finding):
                continue
            exploited.append(finding)
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFORMATIONAL": 4,
            "INFO": 4,
        }
        exploited.sort(
            key=lambda finding: (
                severity_order.get(str(finding.get("severity") or "").upper(), 9),
                str(finding.get("title") or "").strip().lower(),
                str(finding.get("cve_id") or "").strip().lower(),
                str(finding.get("target_url") or "").strip().lower(),
                str(finding.get("resource_id") or "").strip().lower(),
            )
        )
        distinct_cves = {
            str(finding.get("cve_id") or "").strip().upper()
            for finding in exploited
            if str(finding.get("cve_id") or "").strip()
        }
        sev = lambda s: sum(1 for e in exploited if e["severity"] == s)  # noqa: E731
        return ExploitContext(
            finding_count  = len(exploited),
            cve_count      = len(distinct_cves),
            critical_count = sev("CRITICAL"),
            high_count     = sev("HIGH"),
            medium_count   = sev("MEDIUM"),
            exploited      = exploited,
        )

    @staticmethod
    def _finding_is_unvalidated_key_exposure(finding: dict[str, Any]) -> bool:
        vuln_type = str(finding.get("vuln_type") or "").strip().upper()
        title = str(finding.get("title") or "").strip().lower()
        if vuln_type != "DETERMINISTIC_KEY_EXPOSURE" and not title.startswith("active exposed "):
            return False
        return str(finding.get("validation_status") or "").strip().upper() != "VALIDATED"

    @classmethod
    def _finding_is_unvalidated_deterministic_cloud_exposure(
        cls,
        finding: dict[str, Any],
    ) -> bool:
        if not cls._finding_is_deterministic_cloud_exposure(finding):
            return False
        asset_type = str(
            finding.get("validation_asset_type") or finding.get("parameter") or ""
        ).split(":", 1)[0]
        return not is_reportable_cloud_validation(
            asset_type,
            str(finding.get("validation_status") or ""),
            str(finding.get("validation_method") or ""),
            evidence=finding.get("validation_evidence_summary"),
            notes=finding.get("validation_notes"),
            require_stable_proof=True,
        )

    @classmethod
    def _finding_is_deterministic_cloud_exposure(cls, finding: dict[str, Any]) -> bool:
        vuln_type = str(finding.get("vuln_type") or "").strip().upper()
        title = str(finding.get("title") or "").strip().lower()
        if is_deterministic_cloud_exposure(vuln_type, title):
            return True

        parameter_asset = cls._normalize_validation_asset_type(
            str(finding.get("parameter") or "").split(":", 1)[0]
        )
        target_url = str(finding.get("target_url") or "").strip()
        target_asset = ""
        if target_url:
            try:
                parsed = urlsplit(target_url)
            except ValueError:
                parsed = None
            if parsed and parsed.scheme:
                target_asset = cls._normalize_validation_asset_type(parsed.scheme)
        return is_deterministic_cloud_exposure(
            vuln_type,
            title,
            (parameter_asset, target_asset),
        )

    def _load_post_exploit(self, con: sqlite3.Connection) -> PostExploitContext:
        try:
            shells = con.execute(
                "SELECT COUNT(*) FROM payloads WHERE engagement_id=?",
                (self._eid,),
            ).fetchone()[0]
        except sqlite3.OperationalError:
            shells = 0
        try:
            persist = con.execute(
                "SELECT COUNT(*) FROM persistence WHERE engagement_id=?",
                (self._eid,),
            ).fetchone()[0]
        except sqlite3.OperationalError:
            persist = 0
        try:
            lateral_hosts = con.execute(
                "SELECT COUNT(DISTINCT target) FROM lateral_movement "
                "WHERE engagement_id=? AND success=1",
                (self._eid,),
            ).fetchone()[0]
        except sqlite3.OperationalError:
            lateral_hosts = 0
        try:
            exfil = con.execute(
                "SELECT COALESCE(SUM(size_bytes),0) FROM exfiltrated_data "
                "WHERE engagement_id=?",
                (self._eid,),
            ).fetchone()[0]
        except sqlite3.OperationalError:
            exfil = 0
        try:
            techniques_rows = con.execute(
                "SELECT DISTINCT technique FROM lateral_movement WHERE engagement_id=?",
                (self._eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            techniques_rows = []

        artifact_summary = {}
        artifact_type_summary: dict[str, dict[str, int]] = {}
        try:
            rows = con.execute(
                "SELECT artifact_family, COUNT(*) as count FROM exfiltrated_data WHERE engagement_id=? GROUP BY artifact_family",
                (self._eid,),
            ).fetchall()
            artifact_summary = {r["artifact_family"]: r["count"] for r in rows}
        except sqlite3.OperationalError:
            pass
        try:
            subtype_rows = con.execute(
                "SELECT artifact_family, COALESCE(artifact_subtype, 'unknown') AS artifact_subtype, COUNT(*) as count "
                "FROM exfiltrated_data WHERE engagement_id=? GROUP BY artifact_family, artifact_subtype",
                (self._eid,),
            ).fetchall()
            for row in subtype_rows:
                family = row["artifact_family"]
                family_summary = artifact_type_summary.setdefault(family, {})
                family_summary[row["artifact_subtype"]] = row["count"]
        except sqlite3.OperationalError:
            pass

        return PostExploitContext(
            shells_spawned    = shells,
            persistence_count = persist,
            lateral_hosts     = lateral_hosts,
            data_collected_gb = round(exfil / (1024 ** 3), 3) if exfil else 0.0,
            techniques        = [r[0] for r in techniques_rows],
            artifact_summary  = artifact_summary,
            artifact_type_summary = artifact_type_summary,
        )

    def _load_ongoing_intel(self, con: sqlite3.Connection) -> OngoingIntelligenceContext:
        try:
            row = con.execute(
                "SELECT enabled, started_at, keywords_json FROM monitoring_config "
                "WHERE engagement_id=?",
                (self._eid,),
            ).fetchone()
        except sqlite3.OperationalError:
            return OngoingIntelligenceContext()   # table absent — monitoring not configured

        if not row or not row["enabled"]:
            return OngoingIntelligenceContext()

        keywords = json.loads(row["keywords_json"] or "[]")
        window_end = datetime.now(tz=timezone.utc)
        try:
            window_start = datetime.fromisoformat(row["started_at"])
        except (TypeError, ValueError):
            window_start = None

        findings = con.execute(
            "SELECT severity, source_platform, credential_count, plaintext_count "
            "FROM monitoring_findings WHERE engagement_id=? ORDER BY discovered_at DESC",
            (self._eid,),
        ).fetchall()

        high_count = sum(1 for f in findings if f["severity"] == "high")
        cred_total = sum(f["credential_count"] for f in findings)
        plain_total = sum(f["plaintext_count"] for f in findings)
        platforms = list({f["source_platform"] for f in findings})

        narrative = ""
        if findings and window_start:
            narrative = (
                f"Between {window_start.date()} and {window_end.date()}, "
                f"{len(findings)} new paste/breach findings were identified across "
                f"{', '.join(platforms)}. "
                f"Of these, {high_count} are classified as high severity. "
                f"An estimated {cred_total} credentials were exposed "
                f"({plain_total} in plaintext). "
                f"Full paste metadata is available in the Appendix."
            )

        return OngoingIntelligenceContext(
            monitoring_enabled      = True,
            monitored_keywords      = keywords,
            monitoring_window_start = window_start,
            monitoring_window_end   = window_end,
            new_findings_count      = len(findings),
            high_severity_count     = high_count,
            summary_narrative       = narrative,
        )

    def _apply_text_cleaning(self, ctx: ReportContext) -> ReportContext:
        """Stub for --clean-text integration (forge/phase6/cleaner.py)."""
        try:
            from forge.phase6.cleaner import clean_context_fields, CleaningConfig
            cleaned = clean_context_fields(
                ctx.__dict__, config=CleaningConfig.default()
            )
            logger.info("Text cleaning applied to report context.")
        except ImportError:
            logger.debug("forge.phase6.cleaner not available; skipping text cleaning.")
        return ctx


# ── Risk roll-up ───────────────────────────────────────────────────────────────

def _derive_overall_risk(exploits: ExploitContext) -> str:
    """
    Rule-based risk roll-up. Never LLM-derived.

    Priority: CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL
    """
    if exploits.critical_count >= RISK_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if exploits.high_count >= RISK_THRESHOLDS["HIGH"]:
        return "HIGH"
    if exploits.medium_count >= RISK_THRESHOLDS["MEDIUM"]:
        return "HIGH"
    if exploits.medium_count > 0:
        return "MEDIUM"
    if exploits.cve_count > 0:
        return "LOW"
    return "INFORMATIONAL"


# ── Prompt assembler ───────────────────────────────────────────────────────────

class PromptAssembler:
    """
    Renders the Jinja2 prompt template from a ReportContext.

    Token budget: MAX_PROMPT_TOKENS. Raises PromptOverflowError if exceeded.
    Credential leak guard: asserts no plaintext credential patterns in output.
    """

    def __init__(self, template_dir: Path = TEMPLATE_DIR) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            undefined=StrictUndefined,
            autoescape=False,
        )

    def assemble(self, ctx: ReportContext) -> str:
        try:
            tmpl = self._env.get_template(PROMPT_TEMPLATE)
        except TemplateNotFound:
            # Fall back to inline minimal prompt when template absent (dev/test)
            prompt = self._minimal_prompt(ctx)
            self._assert_no_credential_leak(prompt)
            self._assert_within_token_budget(prompt)
            return prompt

        prompt = tmpl.render(
            engagement_name        = ctx.engagement_name,
            operator               = ctx.operator,
            scope                  = ctx.scope,
            start_date             = ctx.start_date,
            end_date               = ctx.end_date,
            overall_risk           = ctx.overall_risk,
            recon                  = ctx.recon,
            osint                  = ctx.osint,
            exploits               = ctx.exploits,
            post_exploitation      = ctx.post_exploitation,
            ongoing_intelligence   = ctx.ongoing_intelligence,
            mandatory_sections     = MANDATORY_SECTIONS,
        )

        self._assert_no_credential_leak(prompt)
        self._assert_within_token_budget(prompt)
        return prompt

    # ------------------------------------------------------------------

    @staticmethod
    def _estimate_prompt_tokens(prompt: str) -> int:
        """Conservative tokenizer-free estimate for provider-agnostic budget gates."""
        byte_count = len(prompt.encode("utf-8", errors="ignore"))
        words_and_marks = len(re.findall(r"\w+|[^\w\s]", prompt, flags=re.UNICODE))
        byte_estimate = (byte_count + 3) // 4
        return max(byte_estimate, words_and_marks)

    @classmethod
    def _assert_within_token_budget(cls, prompt: str) -> None:
        estimated_tokens = cls._estimate_prompt_tokens(prompt)
        if estimated_tokens > MAX_PROMPT_TOKENS:
            raise PromptOverflowError(
                f"estimated prompt tokens {estimated_tokens} exceed budget {MAX_PROMPT_TOKENS}"
            )

    @staticmethod
    def _assert_no_credential_leak(prompt: str) -> None:
        match = _CRED_LEAK_RE.search(prompt)
        if match:
            raise ValueError(
                f"Credential leak detected in assembled prompt: {match.group()!r}. "
                "Audit ContextBuilder — plaintext credentials must never enter the prompt."
            )

    @staticmethod
    def _minimal_prompt(ctx: ReportContext) -> str:
        """Minimal inline prompt used when report_prompt.j2 is absent.

        Prompts stronger LLMs (Claude, GPT-4, Gemini) with actual engagement
        data so they don't refuse "insufficient source material". The local
        Qwen 1.5B model works even without much data because it hallucinates
        freely; cloud providers correctly want facts to synthesise from.
        """
        # Recon block
        hosts_lines = [
            f"  - {h.get('ip_address', '?')} ({h.get('os_guess') or 'unknown OS'})"
            for h in ctx.recon.hosts[:20]
        ] or ["  (no hosts discovered)"]
        ports_lines = [
            f"  - {p.get('ip_address', '?')}:{p.get('port', '?')} → {p.get('service', '?')}"
            for p in ctx.recon.open_ports[:20]
        ] or ["  (no open services)"]

        # Validated findings, if any
        findings = [
            " — ".join(
                part
                for part in (
                    finding.get("cve_id") or finding.get("title"),
                    finding.get("severity"),
                    finding.get("title"),
                )
                if part
            )
            for finding in ctx.exploits.exploited[:10]
        ]
        findings_block = (
            "\nValidated findings:\n- " + "\n- ".join(findings)
            if findings
            else "\nValidated findings: none (correlation only — no live exploitation)"
        )

        return (
            f"You are a senior authorized security assessment report writer.\n"
            f"Produce a professional authorized ASM report for engagement "
            f"'{ctx.engagement_name}' (ID {ctx.engagement_id}, operator "
            f"'{ctx.operator}', overall risk {ctx.overall_risk}).\n\n"
            "SOURCE MATERIAL (from engagement database):\n"
            f"Scope: {', '.join(ctx.scope) if ctx.scope else '<none defined>'}\n\n"
            f"Reconnaissance — {len(ctx.recon.hosts)} host(s), "
            f"{len(ctx.recon.open_ports)} open service(s), "
            f"{len(ctx.recon.subdomains)} subdomain(s):\n"
            + "\n".join(hosts_lines)
            + "\n"
            + "\n".join(ports_lines)
            + "\n\n"
            f"OSINT — {ctx.osint.emails_found} email(s), "
            f"{ctx.osint.credential_hashes} credential hash(es), "
            f"{ctx.osint.email_intelligence_records} email-intelligence record(s) "
            f"from {len(ctx.osint.intelligence_sources)} source(s), "
            f"{ctx.osint.registered_account_count} registered-account hit(s), "
            f"{len(ctx.osint.breach_sources)} breach source(s), "
            f"{ctx.osint.reputation_alert_count} reputation alert(s), "
            f"{ctx.osint.key_findings_count} exposed-key finding(s).\n\n"
            f"Vulnerability and exposure correlation — "
            f"{ctx.exploits.critical_count} critical / "
            f"{ctx.exploits.high_count} high / "
            f"{ctx.exploits.medium_count} medium, "
            f"{ctx.exploits.cve_count} CVE reference(s) across "
            f"{len(ctx.exploits.exploited)} validated finding(s)."
            + findings_block
            + "\n\n"
            "Evidence handling — "
            f"{len(ctx.post_exploitation.artifact_summary)} artifact family bucket(s), "
            f"{sum(len(rows) for rows in ctx.post_exploitation.artifact_type_summary.values())} "
            "artifact type bucket(s), and non-destructive validation evidence "
            "summarised from controlled engagement records.\n\n"
            "INSTRUCTIONS\n"
            "Include all mandatory sections: "
            + ", ".join(s.lstrip("# ") for s in MANDATORY_SECTIONS)
            + ".\n"
            "Write in formal British English. Do not reproduce credential "
            "plaintexts, paste URLs, or raw payloads. Reference "
            "sensitive material by type and count only.\n"
            "Produce the complete Markdown report now, using the source "
            "material above. Do not ask clarifying questions."
        )


# ── Main synthesizer ───────────────────────────────────────────────────────────

class ReportSynthesizer:
    """
    Orchestrates context assembly → prompt rendering → LLM generation →
    validation → disk write.

    The Llama model is loaded lazily on first call to generate() to avoid
    import-time GPU/RAM allocation.

    Args:
        db_path:     Path to the engagement SQLite DB.
        model_path:  Optional override for GGUF model location.
                     Defaults to DEFAULT_MODEL_DIR / MODEL_FILENAME.
        output_dir:  Directory where generated reports are written.
        n_ctx:       Context window size passed to Llama. Default 4096.
        n_threads:   CPU threads for inference. Default 4.
        temperature: Sampling temperature. Default 0.3 (low; factual prose).
        clean_text:  Apply text cleaning pipeline to context before prompting.
    """

    def __init__(
        self,
        db_path:     Path,
        model_path:  Path | None = None,
        output_dir:  Path        = Path("."),
        n_ctx:       int         = 4096,
        n_threads:   int         = 4,
        temperature: float       = 0.3,
        clean_text:  bool        = False,
        assume_yes:  bool        = False,
        provider:    str | None  = None,
        max_correction_loops: int | None = None,
    ) -> None:
        self._db_path     = Path(db_path)
        self._model_path  = model_path or (DEFAULT_MODEL_DIR / MODEL_FILENAME)
        self._output_dir  = Path(output_dir)
        self._n_ctx       = n_ctx
        self._n_threads   = n_threads
        self._temperature = temperature
        self._clean_text  = clean_text
        self._assume_yes  = assume_yes
        self._requested_provider = (provider or "llama_cpp").lower()
        self._provider_name = self._requested_provider
        self._max_loops   = max_correction_loops if max_correction_loops is not None else MAX_CORRECTION_LOOPS
        self._llm         = None         # loaded lazily (llama_cpp path)
        self._llm_provider = None        # loaded lazily (registry path)
        self._render_backend = self._provider_name
        self._fallback_reason = ""

    def _set_render_backend(self, backend: str, *, fallback_reason: str = "") -> None:
        self._render_backend = str(backend or "").strip().lower() or self._provider_name
        self._fallback_reason = str(fallback_reason or "").strip()

    @staticmethod
    def _normalise_auto_provider_token(value: str) -> str:
        token = str(value or "").strip().lower()
        if not token:
            return ""
        token = token.replace("-", "_").replace(" ", "_")
        if token in {"kiro", "kiro_cli"}:
            return "kiro_cli"
        if token.startswith("claude"):
            return "claude_code"
        if token in {"openai", "openai_compatible"} or token.startswith("gpt"):
            return "openai_compatible"
        if token in {"codex", "codex_cli"}:
            return "codex_cli"
        if token.startswith("gemini"):
            return "gemini_cli"
        if token in {"bedrock", "bedrock_anthropic", "aws_bedrock"}:
            return "bedrock_anthropic"
        if token in {"local", "local_llama", "llama", "llama_cpp", "ollama", "lm_studio", "lmstudio"}:
            return "llama_cpp"
        if token == "template":
            return "template"
        return ""

    @classmethod
    def _configured_auto_cascade_order(cls) -> list[str]:
        configured = (
            os.environ.get("FORGE_LLM_CASCADE_ORDER")
            or os.environ.get("LLM_CASCADE_ORDER")
            or ""
        ).strip()
        if not configured:
            return list(_AUTO_CASCADE_DEFAULT_ORDER)

        ordered: list[str] = []
        for raw_token in configured.split(","):
            normalized = cls._normalise_auto_provider_token(raw_token)
            if normalized and normalized not in ordered:
                ordered.append(normalized)
        if not ordered:
            return list(_AUTO_CASCADE_DEFAULT_ORDER)
        for safe_tail in ("llama_cpp", "template"):
            if safe_tail not in ordered:
                ordered.append(safe_tail)
        return ordered

    def _activate_auto_local_backend(self, fallback_reason: str) -> bool:
        if self._provider_name != "auto":
            return False
        try:
            self._ensure_model_loaded(allow_auto_local=True)
        except (ModelNotFoundError, ImportError) as exc:
            logger.warning(
                "Auto cascade local llama_cpp fallback unavailable (%s).",
                exc,
            )
            return False
        if self._llm is None:
            return False
        self._llm_provider = None
        self._set_render_backend("llama_cpp", fallback_reason=fallback_reason)
        logger.info(
            "Auto cascade switched to local llama_cpp backend (%s).",
            fallback_reason,
        )
        return True

    # ------------------------------------------------------------------

    def generate(
        self,
        engagement_id: int,
        include_monitoring: bool = True,
        dry_run: bool = False,
    ) -> Path:
        """
        Generate a report for the given engagement.

        Args:
            engagement_id:       Target engagement DB row ID.
            include_monitoring:  Render Section 8 if monitoring data present.
            dry_run:             Build context + prompt only; skip LLM call.

        Returns:
            Path to the written Markdown report file.

        Raises:
            ModelNotFoundError    — GGUF file absent.
            PromptOverflowError   — prompt exceeds token budget.
            ReportGenerationError — LLM returned empty or malformed output.
        """
        # 1. Build context
        logger.info("Building report context for engagement %d...", engagement_id)
        ctx = ContextBuilder(
            self._db_path, engagement_id, clean_text=self._clean_text
        ).build()

        if not include_monitoring:
            ctx.ongoing_intelligence = OngoingIntelligenceContext()

        # 2. Template mode — no LLM required, ships anywhere.
        # Explicit --provider template short-circuits before assembling
        # prompts or loading models. Faster and 100% deterministic.
        if self._provider_name == "template":
            logger.info("Template mode: rendering factual report directly (no LLM).")
            self._set_render_backend("template")
            return self._persist_report_with_fallback(
                ctx,
                raw_text=self._render_fallback_report(
                    ctx, "Template mode selected explicitly."
                ),
                dry_run=False,
            )

        # 3. Assemble prompt
        assembler = PromptAssembler()
        try:
            prompt = assembler.assemble(ctx)
        except PromptOverflowError as exc:
            logger.warning(
                "Prompt exceeded token budget (%s); falling back to deterministic template.",
                exc,
            )
            self._set_render_backend("template", fallback_reason=str(exc))
            return self._persist_report_with_fallback(
                ctx,
                raw_text=self._render_fallback_report(ctx, str(exc)),
                dry_run=dry_run,
            )
        logger.info("Prompt assembled (%d chars).", len(prompt))

        if dry_run:
            logger.info("Dry-run mode: skipping LLM call.")
            self._set_render_backend("dry_run")
            return self._persist_report_with_fallback(
                ctx,
                raw_text=self._render_skeleton(ctx),
                dry_run=True,
            )

        # 4. Load model (lazy). Auto mode auto-detects available cloud
        # providers; falls back to template if none installed AND local
        # GGUF is absent.
        try:
            self._ensure_model_loaded()
        except (ModelNotFoundError, ImportError) as exc:
            if self._provider_name in (None, "llama_cpp"):
                logger.warning(
                    "llama_cpp model unavailable (%s); falling back to "
                    "template mode.", exc,
                )
                self._set_render_backend("template", fallback_reason=str(exc))
                return self._persist_report_with_fallback(
                    ctx,
                    raw_text=self._render_fallback_report(ctx, str(exc)),
                    dry_run=False,
                )
            raise

        if self._provider_name and self._provider_name != "llama_cpp":
            try:
                self._ensure_provider_loaded()
            except (ValueError, ImportError, ProviderUnavailableError) as exc:
                if self._provider_name == "auto":
                    logger.warning(
                        "Auto cascade cloud backend unavailable (%s); trying local llama_cpp.",
                        exc,
                    )
                    if not self._activate_auto_local_backend(str(exc)):
                        logger.warning(
                            "Auto cascade local fallback unavailable; falling back to template mode."
                        )
                        self._set_render_backend("template", fallback_reason=str(exc))
                        return self._persist_report_with_fallback(
                            ctx,
                            raw_text=self._render_fallback_report(ctx, str(exc)),
                            dry_run=False,
                        )
                    logger.info("Auto cascade continuing with local llama_cpp.")
                else:
                    logger.warning(
                        "LLM provider '%s' unavailable (%s); falling back to deterministic template.",
                        self._provider_name,
                        exc,
                    )
                    self._set_render_backend("template", fallback_reason=str(exc))
                    return self._persist_report_with_fallback(
                        ctx,
                        raw_text=self._render_fallback_report(ctx, str(exc)),
                        dry_run=False,
                    )

        # 4. Generate and iteratively self-correct
        from forge.phase6.llm_validator import validate_report
        logger.info("Running inference (this may take 30–60 s on CPU)...")
        response_text = ""
        telemetry = ValidationTelemetry(
            quality_score=0.0,
            correction_loops=0,
            feedback_text="",
            narrative_coherence_score=0.0,
            opsec_violation_count=0,
            hallucination_score=1.0,
            factual_accuracy_score=0.0,
            engagement_context_relevance=0.0,
            validator_ok=False,
            final_approval=False,
        )

        revision_prompt = prompt
        if not (self._provider_name == "auto" and self._llm_provider is None and self._llm is not None):
            self._set_render_backend(self._provider_name)
        for attempt in range(self._max_loops + 1):
            t0 = time.monotonic()
            try:
                response_text = self._infer(revision_prompt)
            except ProviderUnavailableError as exc:
                if self._provider_name == "auto" and self._llm_provider is not None:
                    logger.warning(
                        "Auto cascade cloud execution failed (%s); retrying with local llama_cpp.",
                        exc,
                    )
                    if self._activate_auto_local_backend(str(exc)):
                        try:
                            response_text = self._infer(revision_prompt)
                        except ProviderUnavailableError as local_exc:
                            logger.warning(
                                "Local llama_cpp fallback failed (%s); falling back to deterministic template.",
                                local_exc,
                            )
                            self._set_render_backend("template", fallback_reason=str(local_exc))
                            response_text = self._render_fallback_report(ctx, str(local_exc))
                            telemetry = ValidationTelemetry(
                                quality_score=0.0,
                                correction_loops=attempt,
                                feedback_text=f"template_fallback: {local_exc}",
                                narrative_coherence_score=0.0,
                                opsec_violation_count=0,
                                hallucination_score=0.0,
                                factual_accuracy_score=1.0,
                                engagement_context_relevance=1.0,
                                validator_ok=False,
                                final_approval=False,
                            )
                            break
                    else:
                        logger.warning(
                            "Local llama_cpp fallback unavailable; falling back to deterministic template."
                        )
                        self._set_render_backend("template", fallback_reason=str(exc))
                        response_text = self._render_fallback_report(ctx, str(exc))
                        telemetry = ValidationTelemetry(
                            quality_score=0.0,
                            correction_loops=attempt,
                            feedback_text=f"template_fallback: {exc}",
                            narrative_coherence_score=0.0,
                            opsec_violation_count=0,
                            hallucination_score=0.0,
                            factual_accuracy_score=1.0,
                            engagement_context_relevance=1.0,
                            validator_ok=False,
                            final_approval=False,
                        )
                        break
                else:
                    logger.warning(
                        "LLM provider execution failed (%s); falling back to deterministic template.",
                        exc,
                    )
                    self._set_render_backend("template", fallback_reason=str(exc))
                    response_text = self._render_fallback_report(ctx, str(exc))
                    telemetry = ValidationTelemetry(
                        quality_score=0.0,
                        correction_loops=attempt,
                        feedback_text=f"template_fallback: {exc}",
                        narrative_coherence_score=0.0,
                        opsec_violation_count=0,
                        hallucination_score=0.0,
                        factual_accuracy_score=1.0,
                        engagement_context_relevance=1.0,
                        validator_ok=False,
                        final_approval=False,
                    )
                    break
            elapsed = time.monotonic() - t0
            logger.info("Inference attempt %d complete in %.1f s.", attempt + 1, elapsed)
            if not response_text or len(response_text.strip()) < 100:
                logger.warning(
                    "LLM returned an empty or trivially short completion (%d chars); "
                    "falling back to deterministic template.",
                    len(response_text),
                )
                self._set_render_backend(
                    "template",
                    fallback_reason=f"short completion ({len(response_text)} chars)",
                )
                response_text = self._render_fallback_report(
                    ctx,
                    f"LLM returned an empty or trivially short completion ({len(response_text)} chars).",
                )
                telemetry = ValidationTelemetry(
                    quality_score=0.0,
                    correction_loops=attempt,
                    feedback_text="template_fallback: short completion",
                    narrative_coherence_score=0.0,
                    opsec_violation_count=0,
                    hallucination_score=0.0,
                    factual_accuracy_score=1.0,
                    engagement_context_relevance=1.0,
                    validator_ok=False,
                    final_approval=False,
                )
                break

            integrity_failures = self._authoritative_finding_integrity_failures(
                ctx,
                response_text,
            )
            if integrity_failures:
                reason = (
                    "LLM output failed authoritative finding integrity check: "
                    + "; ".join(integrity_failures[:5])
                )
                logger.warning("%s", reason)
                self._set_render_backend("template", fallback_reason=reason)
                response_text = self._render_fallback_report(ctx, reason)
                telemetry = ValidationTelemetry(
                    quality_score=0.0,
                    correction_loops=attempt,
                    feedback_text=f"template_fallback: {reason}",
                    narrative_coherence_score=0.0,
                    opsec_violation_count=0,
                    hallucination_score=0.0,
                    factual_accuracy_score=1.0,
                    engagement_context_relevance=1.0,
                    validator_ok=False,
                    final_approval=False,
                )
                break

            result = validate_report(
                raw_text=response_text,
                overall_risk=ctx.overall_risk,
                ongoing_intel=ctx.ongoing_intelligence,
                approved_internal_ips=[h.get("ip_address") for h in ctx.recon.hosts if h.get("ip_address")],
            )
            telemetry = self._build_validation_telemetry(
                ctx=ctx,
                report_text=response_text,
                validation_result=result,
                correction_loops=attempt,
            )
            if telemetry.final_approval:
                logger.info(
                    "Validation accepted on attempt %d (quality=%.3f).",
                    attempt + 1,
                    telemetry.quality_score,
                )
                break
            if attempt >= self._max_loops:
                logger.warning(
                    "Validation did not converge after %d attempts (quality=%.3f).",
                    self._max_loops + 1,
                    telemetry.quality_score,
                )
                break
            revision_prompt = self._build_revision_prompt(
                base_prompt=prompt,
                previous_report=response_text,
                feedback_text=telemetry.feedback_text,
            )

        # 5. Persist telemetry
        self._persist_feedback(
            engagement_id=engagement_id,
            prompt_text=prompt,
            response_text=response_text,
            telemetry=telemetry,
        )

        # 6. Confirm write
        if not telemetry.validator_ok:
            logger.warning("Validation failed; writing report with review warning.")
        out = self._persist_report_with_fallback(ctx, raw_text=response_text)
        return out

    def _build_validation_telemetry(
        self,
        ctx: ReportContext,
        report_text: str,
        validation_result: Any,
        correction_loops: int,
    ) -> ValidationTelemetry:
        narrative_score = self._score_narrative_coherence(report_text)
        opsec_hits = self._detect_opsec_violations(report_text)
        opsec_compliance = max(0.0, 1.0 - min(1.0, len(opsec_hits) / 5.0))
        factual_score, hallucination_score = self._score_factual_accuracy(
            report_text, ctx.exploits.exploited
        )
        relevance_score = self._score_engagement_relevance(report_text, ctx)
        quality_score = (
            narrative_score * QUALITY_WEIGHTS["narrative_coherence"]
            + factual_score * QUALITY_WEIGHTS["factual_accuracy"]
            + opsec_compliance * QUALITY_WEIGHTS["opsec_compliance"]
            + relevance_score * QUALITY_WEIGHTS["engagement_relevance"]
        )
        feedback = self._build_feedback_text(
            validation_result=validation_result,
            narrative_score=narrative_score,
            factual_score=factual_score,
            hallucination_score=hallucination_score,
            relevance_score=relevance_score,
            opsec_hits=opsec_hits,
            quality_score=quality_score,
        )
        final_approval = (
            validation_result.passed
            and quality_score >= MIN_QUALITY_SCORE
            and len(opsec_hits) == 0
            and hallucination_score <= 0.10
        )
        return ValidationTelemetry(
            quality_score=round(quality_score, 4),
            correction_loops=correction_loops,
            feedback_text=feedback,
            narrative_coherence_score=round(narrative_score, 4),
            opsec_violation_count=len(opsec_hits),
            hallucination_score=round(hallucination_score, 4),
            factual_accuracy_score=round(factual_score, 4),
            engagement_context_relevance=round(relevance_score, 4),
            validator_ok=bool(validation_result.passed),
            final_approval=final_approval,
        )

    @staticmethod
    def _score_narrative_coherence(report_text: str) -> float:
        section_coverage = sum(1 for section in MANDATORY_SECTIONS if section in report_text) / len(MANDATORY_SECTIONS)
        word_count = len(report_text.split())
        density_score = min(1.0, word_count / 700.0)
        return min(1.0, 0.65 * section_coverage + 0.35 * density_score)

    @staticmethod
    def _extract_cves(text: str) -> set[str]:
        return set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE))

    def _score_factual_accuracy(
        self,
        report_text: str,
        exploited_findings: list[dict[str, Any]],
    ) -> tuple[float, float]:
        known_cves = {
            str(item.get("cve_id", "")).upper()
            for item in exploited_findings
            if item.get("cve_id")
        }
        mentioned_cves = {cve.upper() for cve in self._extract_cves(report_text)}
        if not known_cves and not mentioned_cves:
            return 1.0, 0.0
        if not mentioned_cves:
            return 1.0, 0.0
        matched = len(mentioned_cves & known_cves)
        hallucinated = len(mentioned_cves - known_cves)
        factual_score = matched / max(1, len(mentioned_cves))
        hallucination_score = hallucinated / max(1, len(mentioned_cves))
        return factual_score, hallucination_score

    @staticmethod
    def _authoritative_finding_integrity_failures(
        ctx: ReportContext,
        report_text: str,
    ) -> list[str]:
        report_lower = " ".join(str(report_text or "").lower().split())
        failures: list[str] = []
        for finding in ctx.exploits.exploited:
            title = str(finding.get("title") or finding.get("cve_id") or "").strip()
            severity = str(finding.get("severity") or "").strip().upper()
            if not title:
                continue
            title_lower = " ".join(title.lower().split())
            title_pos = report_lower.find(title_lower)
            if title_pos < 0:
                failures.append(f"missing finding title '{title[:80]}'")
                continue
            if not severity:
                continue
            window = report_lower[
                max(0, title_pos - 240): title_pos + len(title_lower) + 240
            ]
            labels = ("critical", "high", "medium", "low", "info")
            prefix = report_lower[max(0, title_pos - 120): title_pos]
            suffix = report_lower[title_pos + len(title_lower): title_pos + len(title_lower) + 80]
            prefix_matches = [
                (len(prefix) - match.end(), label)
                for label in labels
                for match in re.finditer(rf"\b{label}\b", prefix)
            ]
            suffix_matches = [
                (match.start(), label)
                for label in labels
                for match in re.finditer(rf"\b{label}\b", suffix)
            ]
            nearest_label = min(prefix_matches + suffix_matches, default=None)
            if nearest_label and nearest_label[1] != severity.lower():
                failures.append(
                    f"conflicting severity {nearest_label[1].upper()} near '{title[:80]}'"
                )
                continue
            if severity.lower() not in window:
                failures.append(f"missing severity {severity} near '{title[:80]}'")
        return failures

    @staticmethod
    def _detect_opsec_violations(report_text: str) -> list[str]:
        patterns = [
            r"\b(?:(?:10|127|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}|(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})\b",
            r"(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+",
            r"(?i)\b(?:metasploit|msfvenom|burp|sqlmap|nmap|cobalt strike)\b",
            r"(?i)\b(?:C2|beacon|named pipe|lateral movement playbook|exploit chain|lateral movement|persistence establishment|data exfiltration)\b",
        ]
        violations: list[str] = []
        for pattern in patterns:
            violations.extend(match.group(0) for match in re.finditer(pattern, report_text))
        return violations

    @staticmethod
    def _score_engagement_relevance(report_text: str, ctx: ReportContext) -> float:
        section_coverage = sum(1 for section in MANDATORY_SECTIONS if section in report_text) / len(MANDATORY_SECTIONS)
        has_risk_reference = ctx.overall_risk.lower() in report_text.lower()
        return min(1.0, (0.7 * section_coverage) + (0.3 if has_risk_reference else 0.0))

    @staticmethod
    def _build_feedback_text(
        validation_result: Any,
        narrative_score: float,
        factual_score: float,
        hallucination_score: float,
        relevance_score: float,
        opsec_hits: list[str],
        quality_score: float,
    ) -> str:
        feedback_parts: list[str] = []
        if not validation_result.passed:
            feedback_parts.append("Resolve validator errors and warnings.")
        if narrative_score < 0.85:
            feedback_parts.append("Improve section completeness and narrative flow.")
        if factual_score < 0.90:
            feedback_parts.append("Align all CVE and finding references with database evidence.")
        if hallucination_score > 0.10:
            feedback_parts.append("Remove findings that are not present in engagement data.")
        if relevance_score < 0.80:
            feedback_parts.append("Increase scope and engagement-context specificity.")
        if opsec_hits:
            feedback_parts.append("Eliminate OPSEC-sensitive details and tool disclosures.")
        if quality_score < MIN_QUALITY_SCORE:
            feedback_parts.append("Raise overall quality score above acceptance threshold.")
        if not feedback_parts:
            feedback_parts.append("Validation passed with acceptable quality.")
        return " ".join(feedback_parts)

    @staticmethod
    def _build_revision_prompt(
        base_prompt: str,
        previous_report: str,
        feedback_text: str,
    ) -> str:
        return (
            f"{base_prompt}\n\n"
            "Revise the previous draft using the following validation feedback.\n"
            f"Feedback: {feedback_text}\n"
            "Return only the fully revised final report.\n\n"
            "Previous Draft:\n"
            f"{previous_report}"
        )

    @staticmethod
    def _sha256_hex(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    def _findings_checksum(self, ctx: ReportContext) -> str:
        payload = json.dumps(asdict(ctx), sort_keys=True, default=str)
        return self._sha256_hex(payload)

    def _report_lineage_payload(
        self,
        ctx: ReportContext,
        *,
        generated_at: str | None = None,
        provider: str | None = None,
        format_name: str = "markdown",
        write_error: str | None = None,
    ) -> dict[str, Any]:
        rendered_provider = str(provider or self._render_backend or self._provider_name or "").strip()
        fallback_reason = str(self._fallback_reason or "").strip()
        payload: dict[str, Any] = {
            "requested_provider": self._requested_provider,
            "rendered_provider": rendered_provider,
            "format": format_name,
            "findings_checksum": f"sha256:{self._findings_checksum(ctx)}",
            "fallback_reason": fallback_reason or None,
        }
        if generated_at is not None:
            payload["generated_at"] = generated_at
        if write_error:
            payload["write_error"] = write_error
        return payload

    def _render_report_lineage_block(self, ctx: ReportContext) -> str:
        lineage = self._report_lineage_payload(ctx)
        fallback_reason = str(lineage.get("fallback_reason") or "none")
        return "\n".join(
            [
                "## Report Generation Lineage",
                "",
                f"- **Requested provider:** {lineage['requested_provider']}",
                f"- **Rendered provider:** {lineage['rendered_provider'] or '<unknown>'}",
                f"- **Fallback reason:** {fallback_reason}",
                f"- **Structured-data checksum:** `{lineage['findings_checksum']}`",
            ]
        )

    def _render_fallback_report(self, ctx: ReportContext, reason: str) -> str:
        return (
            f"{self._render_skeleton(ctx).rstrip()}\n\n"
            "---\n\n"
            f"_LLM fallback engaged: {reason}_\n"
        )

    def _decorate_report(self, ctx: ReportContext, raw_text: str, dry_run: bool) -> str:
        lines = [raw_text.rstrip(), "", "---", ""]
        if dry_run:
            lines.append("_Dry-run mode: no live LLM inference was executed._")
            lines.append("")
        lines.append(
            f"Data integrity checksum (structured input): `sha256:{self._findings_checksum(ctx)}`"
        )
        lines.extend(["", self._render_report_lineage_block(ctx)])
        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _json_safe(value: Any) -> Any:
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, dict):
            return {str(key): ReportSynthesizer._json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [ReportSynthesizer._json_safe(item) for item in value]
        return value

    def _report_export_payload(
        self,
        ctx: ReportContext,
        markdown_text: str,
        *,
        dry_run: bool,
        generated_at: str,
    ) -> dict[str, Any]:
        context_payload = self._json_safe(asdict(ctx))
        lineage = self._report_lineage_payload(ctx, generated_at=generated_at)
        return {
            "engagement_id": ctx.engagement_id,
            "engagement_name": ctx.engagement_name,
            "operator": ctx.operator,
            "provider": self._render_backend,
            "requested_provider": self._requested_provider,
            "generated_at": generated_at,
            "dry_run": dry_run,
            "overall_risk": ctx.overall_risk,
            "findings_checksum": f"sha256:{self._findings_checksum(ctx)}",
            "format": "markdown",
            "report_markdown": markdown_text,
            "fallback_reason": self._fallback_reason or None,
            "report_lineage": lineage,
            "context": context_payload,
        }

    @staticmethod
    def _pdf_escape(text: str) -> str:
        return (
            text.encode("latin-1", errors="replace")
            .decode("latin-1")
            .replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
        )

    @classmethod
    def _write_minimal_pdf(cls, path: Path, title: str, text: str) -> None:
        wrapper = TextWrapper(
            width=92,
            break_long_words=True,
            drop_whitespace=False,
            replace_whitespace=False,
        )
        wrapped_lines: list[str] = []
        for line in text.replace("\r\n", "\n").split("\n"):
            if not line:
                wrapped_lines.append("")
                continue
            wrapped = wrapper.wrap(line)
            wrapped_lines.extend(wrapped or [""])
        lines_per_page = 48
        pages = [
            wrapped_lines[index:index + lines_per_page]
            for index in range(0, max(len(wrapped_lines), 1), lines_per_page)
        ]
        if not pages:
            pages = [[""]]

        page_count = len(pages)
        catalog_id = 1
        pages_id = 2
        first_page_id = 3
        font_id = first_page_id + (page_count * 2)
        objects: dict[int, bytes] = {}
        kid_refs: list[str] = []

        for index, page_lines in enumerate(pages):
            page_id = first_page_id + (index * 2)
            content_id = page_id + 1
            kid_refs.append(f"{page_id} 0 R")
            content_lines = ["BT", "/F1 11 Tf", "14 TL", "50 760 Td"]
            for line_index, line in enumerate(page_lines):
                if line_index > 0:
                    content_lines.append("T*")
                content_lines.append(f"({cls._pdf_escape(line)}) Tj")
            content_lines.append("ET")
            stream = "\n".join(content_lines).encode("latin-1", errors="replace")
            objects[content_id] = (
                f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
                + stream
                + b"\nendstream"
            )
            objects[page_id] = (
                f"<< /Type /Page /Parent {pages_id} 0 R "
                f"/MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 {font_id} 0 R >> >> "
                f"/Contents {content_id} 0 R >>"
            ).encode("ascii")

        objects[catalog_id] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")
        objects[pages_id] = (
            f"<< /Type /Pages /Kids [{' '.join(kid_refs)}] /Count {page_count} >>"
        ).encode("ascii")
        objects[font_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        info_id = font_id + 1
        objects[info_id] = (
            f"<< /Title ({cls._pdf_escape(title)}) /Producer (FORGE ReportSynthesizer) >>"
        ).encode("latin-1", errors="replace")

        pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0] * (info_id + 1)
        for object_id in range(1, info_id + 1):
            offsets[object_id] = len(pdf)
            pdf.extend(f"{object_id} 0 obj\n".encode("ascii"))
            pdf.extend(objects[object_id])
            pdf.extend(b"\nendobj\n")

        xref_offset = len(pdf)
        pdf.extend(f"xref\n0 {info_id + 1}\n".encode("ascii"))
        pdf.extend(b"0000000000 65535 f \n")
        for object_id in range(1, info_id + 1):
            pdf.extend(f"{offsets[object_id]:010d} 00000 n \n".encode("ascii"))
        pdf.extend(
            (
                f"trailer\n<< /Size {info_id + 1} /Root {catalog_id} 0 R /Info {info_id} 0 R >>\n"
                f"startxref\n{xref_offset}\n%%EOF"
            ).encode("ascii")
        )
        path.write_bytes(bytes(pdf))

    def _write_companion_exports(
        self,
        ctx: ReportContext,
        markdown_path: Path,
        markdown_text: str,
        *,
        dry_run: bool,
    ) -> dict[str, Path]:
        generated_at = datetime.now(tz=timezone.utc).isoformat()
        json_path = markdown_path.with_suffix(".json")
        pdf_path = markdown_path.with_suffix(".pdf")
        csv_path = markdown_path.with_suffix(".csv")
        payload = self._report_export_payload(
            ctx,
            markdown_text,
            dry_run=dry_run,
            generated_at=generated_at,
        )
        json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        self._write_minimal_pdf(
            pdf_path,
            title=f"FORGE Engagement Report {ctx.engagement_id}",
            text=markdown_text,
        )
        self._write_raw_export_csv_file(ctx, csv_path, report_metadata=payload["report_lineage"])
        return {
            "markdown": markdown_path,
            "json": json_path,
            "pdf": pdf_path,
            "csv": csv_path,
        }

    @staticmethod
    def _csv_report_metadata(report_metadata: Mapping[str, Any] | None) -> dict[str, object]:
        metadata = report_metadata or {}
        return {
            "findings_checksum": str(metadata.get("findings_checksum") or ""),
            "report_requested_provider": str(metadata.get("requested_provider") or ""),
            "report_rendered_provider": str(metadata.get("rendered_provider") or ""),
            "report_format": str(metadata.get("format") or ""),
            "report_generated_at": str(metadata.get("generated_at") or ""),
            "fallback_reason": str(metadata.get("fallback_reason") or ""),
            "report_write_error": str(metadata.get("write_error") or metadata.get("report_write_error") or ""),
        }

    @staticmethod
    def _raw_export_csv_rows(
        ctx: ReportContext,
        report_metadata: Mapping[str, Any] | None = None,
    ) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for finding in ctx.exploits.exploited:
            rows.append(
                {
                    "record_type": "finding",
                    "engagement_id": ctx.engagement_id,
                    "engagement_name": ctx.engagement_name,
                    "overall_risk": ctx.overall_risk,
                    "severity": str(finding.get("severity") or ""),
                    "cve_id": str(finding.get("cve_id") or ""),
                    "title": str(finding.get("title") or ""),
                    "evidence": str(finding.get("evidence") or ""),
                    "target_url": str(finding.get("target_url") or ""),
                    "parameter": str(finding.get("parameter") or ""),
                    "cloud_provider": str(finding.get("cloud_provider") or ""),
                    "resource_id": str(finding.get("resource_id") or ""),
                    "validation_status": str(finding.get("validation_status") or ""),
                    "validation_method": str(finding.get("validation_method") or ""),
                    "validation_http_status": str(finding.get("validation_http_status") or ""),
                    "seed_type": "",
                    "seed_value": "",
                    "seed_source": "",
                    "seed_depth": "",
                    "seed_confidence": "",
                    "relation_source": "",
                    "relation_type": "",
                    "relation_target": "",
                    "relation_confidence": "",
                    "relation_evidence": "",
                    "emails_found": ctx.osint.emails_found,
                    "hosts_found": len(ctx.recon.hosts),
                    "subdomains_found": len(ctx.recon.subdomains),
                    "open_ports_found": len(ctx.recon.open_ports),
                    "key_findings_count": ctx.osint.key_findings_count,
                }
            )
        for validation in ctx.cloud_validation_inventory:
            rows.append(
                {
                    "record_type": "cloud_validation",
                    "engagement_id": ctx.engagement_id,
                    "engagement_name": ctx.engagement_name,
                    "overall_risk": ctx.overall_risk,
                    "validation_status": str(validation.get("validation_status") or ""),
                    "validation_method": str(validation.get("method") or ""),
                    "validation_http_status": str(validation.get("http_status") or ""),
                    "cloud_asset_type": str(validation.get("asset_type") or ""),
                    "cloud_identifier": str(validation.get("identifier") or ""),
                    "cloud_provider_identifier": str(
                        validation.get("provider_identifier") or ""
                    ),
                    "validation_checked_at": str(validation.get("checked_at") or ""),
                    "validation_notes": str(validation.get("notes") or ""),
                    "validation_evidence_summary": str(
                        validation.get("evidence_summary") or ""
                    ),
                    "emails_found": ctx.osint.emails_found,
                    "hosts_found": len(ctx.recon.hosts),
                    "subdomains_found": len(ctx.recon.subdomains),
                    "open_ports_found": len(ctx.recon.open_ports),
                    "key_findings_count": ctx.osint.key_findings_count,
                }
            )
        for seed in ctx.seed_summary.seeds:
            rows.append(
                {
                    "record_type": "seed",
                    "engagement_id": ctx.engagement_id,
                    "engagement_name": ctx.engagement_name,
                    "overall_risk": ctx.overall_risk,
                    "severity": "",
                    "cve_id": "",
                    "title": "",
                    "evidence": "",
                    "validation_status": "",
                    "validation_method": "",
                    "validation_http_status": "",
                    "seed_type": str(seed.get("type") or ""),
                    "seed_value": str(seed.get("value") or ""),
                    "seed_source": str(seed.get("source") or ""),
                    "seed_depth": str(seed.get("depth") or ""),
                    "seed_confidence": str(seed.get("confidence") or ""),
                    "relation_source": "",
                    "relation_type": "",
                    "relation_target": "",
                    "relation_confidence": "",
                    "relation_evidence": "",
                    "emails_found": ctx.osint.emails_found,
                    "hosts_found": len(ctx.recon.hosts),
                    "subdomains_found": len(ctx.recon.subdomains),
                    "open_ports_found": len(ctx.recon.open_ports),
                    "key_findings_count": ctx.osint.key_findings_count,
                }
            )
        for relation in ctx.seed_summary.relations:
            rows.append(
                {
                    "record_type": "seed_relation",
                    "engagement_id": ctx.engagement_id,
                    "engagement_name": ctx.engagement_name,
                    "overall_risk": ctx.overall_risk,
                    "severity": "",
                    "cve_id": "",
                    "title": "",
                    "evidence": "",
                    "validation_status": "",
                    "validation_method": "",
                    "validation_http_status": "",
                    "seed_type": "",
                    "seed_value": "",
                    "seed_source": "",
                    "seed_depth": "",
                    "seed_confidence": "",
                    "relation_source": str(relation.get("source_value") or ""),
                    "relation_type": str(relation.get("relation_type") or ""),
                    "relation_target": str(relation.get("target_value") or ""),
                    "relation_confidence": str(relation.get("confidence") or ""),
                    "relation_evidence": str(relation.get("evidence") or ""),
                    "emails_found": ctx.osint.emails_found,
                    "hosts_found": len(ctx.recon.hosts),
                    "subdomains_found": len(ctx.recon.subdomains),
                    "open_ports_found": len(ctx.recon.open_ports),
                    "key_findings_count": ctx.osint.key_findings_count,
                }
            )
        for archive_url in ctx.recon.archive_urls:
            rows.append(
                {
                    "record_type": "archive_url",
                    "engagement_id": ctx.engagement_id,
                    "engagement_name": ctx.engagement_name,
                    "overall_risk": ctx.overall_risk,
                    "severity": "",
                    "cve_id": "",
                    "title": str(archive_url.get("title") or ""),
                    "evidence": "",
                    "validation_status": "",
                    "validation_method": "",
                    "validation_http_status": "",
                    "seed_type": "",
                    "seed_value": "",
                    "seed_source": "",
                    "seed_depth": "",
                    "seed_confidence": "",
                    "relation_source": "",
                    "relation_type": "",
                    "relation_target": "",
                    "relation_confidence": "",
                    "relation_evidence": "",
                    "archive_url": str(archive_url.get("url") or ""),
                    "archive_sources": ",".join(str(source) for source in archive_url.get("sources", []) or []),
                    "archive_root_domain": str(archive_url.get("root_domain") or ""),
                    "archive_discovered_from": str(archive_url.get("discovered_from") or ""),
                    "emails_found": ctx.osint.emails_found,
                    "hosts_found": len(ctx.recon.hosts),
                    "subdomains_found": len(ctx.recon.subdomains),
                    "open_ports_found": len(ctx.recon.open_ports),
                    "key_findings_count": ctx.osint.key_findings_count,
                }
            )
        archive_defaults = {
            "archive_url": "",
            "archive_sources": "",
            "archive_root_domain": "",
            "archive_discovered_from": "",
        }
        cloud_validation_defaults = {
            "cloud_asset_type": "",
            "cloud_identifier": "",
            "cloud_provider_identifier": "",
            "validation_checked_at": "",
            "validation_notes": "",
            "validation_evidence_summary": "",
        }
        report_defaults = ReportSynthesizer._csv_report_metadata(report_metadata)
        for row in rows:
            for key, value in archive_defaults.items():
                row.setdefault(key, value)
            for key, value in cloud_validation_defaults.items():
                row.setdefault(key, value)
            row.update(report_defaults)
            for key in (
                "severity",
                "cve_id",
                "title",
                "evidence",
                "target_url",
                "parameter",
                "cloud_provider",
                "resource_id",
                "validation_status",
                "validation_method",
                "validation_http_status",
                "seed_type",
                "seed_value",
                "seed_source",
                "seed_depth",
                "seed_confidence",
                "relation_source",
                "relation_type",
                "relation_target",
                "relation_confidence",
                "relation_evidence",
            ):
                row.setdefault(key, "")
        if rows:
            return rows
        return [
            {
                "record_type": "summary",
                "engagement_id": ctx.engagement_id,
                "engagement_name": ctx.engagement_name,
                "overall_risk": ctx.overall_risk,
                "severity": "",
                "cve_id": "",
                "title": "",
                "evidence": "",
                "validation_status": "",
                "validation_method": "",
                "validation_http_status": "",
                "seed_type": "",
                "seed_value": "",
                "seed_source": "",
                "seed_depth": "",
                "seed_confidence": "",
                "relation_source": "",
                "relation_type": "",
                "relation_target": "",
                "relation_confidence": "",
                "relation_evidence": "",
                "archive_url": "",
                "archive_sources": "",
                "archive_root_domain": "",
                "archive_discovered_from": "",
                "cloud_asset_type": "",
                "cloud_identifier": "",
                "cloud_provider_identifier": "",
                "validation_checked_at": "",
                "validation_notes": "",
                "validation_evidence_summary": "",
                **report_defaults,
                "emails_found": ctx.osint.emails_found,
                "hosts_found": len(ctx.recon.hosts),
                "subdomains_found": len(ctx.recon.subdomains),
                "open_ports_found": len(ctx.recon.open_ports),
                "key_findings_count": ctx.osint.key_findings_count,
            }
        ]

    @classmethod
    def _write_raw_export_csv_file(
        cls,
        ctx: ReportContext,
        csv_path: Path,
        report_metadata: Mapping[str, Any] | None = None,
    ) -> None:
        csv_rows = cls._raw_export_csv_rows(ctx, report_metadata=report_metadata)
        csv_columns = list(csv_rows[0].keys())
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=csv_columns)
            writer.writeheader()
            writer.writerows(csv_rows)

    def _write_raw_export_fallback(
        self,
        ctx: ReportContext,
        *,
        dry_run: bool,
        write_error: Exception,
    ) -> Path:
        generated_at = datetime.now(tz=timezone.utc).isoformat()
        reason_parts = [
            part
            for part in (
                self._fallback_reason,
                f"{type(write_error).__name__}: {write_error}",
            )
            if str(part or "").strip()
        ]
        fallback_reason = " | ".join(reason_parts)
        context_payload = self._json_safe(asdict(ctx))
        write_error_detail = f"{type(write_error).__name__}: {write_error}"
        lineage = self._report_lineage_payload(
            ctx,
            generated_at=generated_at,
            provider="raw_export",
            format_name="raw_export",
            write_error=write_error_detail,
        )
        lineage["fallback_reason"] = fallback_reason or None
        payload = {
            "engagement_id": ctx.engagement_id,
            "engagement_name": ctx.engagement_name,
            "operator": ctx.operator,
            "provider": "raw_export",
            "requested_provider": self._requested_provider,
            "upstream_provider": self._render_backend or self._provider_name,
            "generated_at": generated_at,
            "dry_run": dry_run,
            "overall_risk": ctx.overall_risk,
            "findings_checksum": f"sha256:{self._findings_checksum(ctx)}",
            "format": "raw_export",
            "report_markdown": "",
            "fallback_reason": fallback_reason or None,
            "report_write_error": write_error_detail,
            "report_lineage": lineage,
            "render_note": (
                "Report-family rendering or export persistence failed. "
                "Raw structured export was emitted as the last-resort fallback."
            ),
            "context": context_payload,
        }

        output_candidates = [self._output_dir]
        temp_candidate = Path(tempfile.gettempdir()) / "forge-report-fallback"
        if temp_candidate not in output_candidates:
            output_candidates.append(temp_candidate)

        last_error: Exception | None = None
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S")
        stem = f"engagement_{ctx.engagement_id}_raw_export_{ts}"

        for candidate_dir in output_candidates:
            try:
                candidate_dir.mkdir(parents=True, exist_ok=True)
                json_path = candidate_dir / f"{stem}.json"
                csv_path = candidate_dir / f"{stem}.csv"
                json_path.write_text(
                    json.dumps(payload, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                self._write_raw_export_csv_file(ctx, csv_path, report_metadata=lineage)
                logger.warning(
                    "Report-family write failed; emitted raw export fallback to %s",
                    json_path,
                )
                return json_path
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue

        raise ReportGenerationError(
            "Report-family write failed and raw export fallback could not be persisted: "
            f"{last_error or write_error}"
        )

    def _persist_feedback(
        self,
        engagement_id: int,
        prompt_text: str,
        response_text: str,
        telemetry: ValidationTelemetry,
    ) -> None:
        try:
            con = sqlite3.connect(self._db_path)
            try:
                try:
                    apply_schema(con)
                    run_migrations(con)
                except Exception:
                    self._ensure_feedback_schema(con)
                con.execute(
                    """
                    INSERT INTO llm_feedback (
                        engagement_id, model, prompt_hash, response_hash, quality_score,
                        validator_ok, correction_loops, feedback_text,
                        narrative_coherence_score, opsec_violation_count, hallucination_score,
                        factual_accuracy_score, engagement_context_relevance, final_approval,
                        validation_timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (
                        engagement_id,
                        self._model_path.stem,
                        self._sha256_hex(prompt_text),
                        self._sha256_hex(response_text),
                        telemetry.quality_score,
                        int(telemetry.validator_ok),
                        telemetry.correction_loops,
                        telemetry.feedback_text,
                        telemetry.narrative_coherence_score,
                        telemetry.opsec_violation_count,
                        telemetry.hallucination_score,
                        telemetry.factual_accuracy_score,
                        telemetry.engagement_context_relevance,
                        int(telemetry.final_approval),
                    ),
                )
                con.commit()
            finally:
                con.close()
        except Exception as exc:
            logger.warning("Unable to persist LLM feedback telemetry: %s", exc)

    def _persist_report_with_fallback(
        self,
        ctx: ReportContext,
        *,
        raw_text: str,
        dry_run: bool = False,
    ) -> Path:
        try:
            return self._write_report(ctx, raw_text=raw_text, dry_run=dry_run)
        except RuntimeError:
            raise
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            logger.warning(
                "Report-family persistence failed (%s); falling back to raw structured export.",
                exc,
            )
            return self._write_raw_export_fallback(
                ctx,
                dry_run=dry_run,
                write_error=exc,
            )

    @staticmethod
    def _safe_add_column(con: sqlite3.Connection, sql: str) -> None:
        try:
            con.execute(sql)
        except sqlite3.OperationalError as exc:
            if "duplicate column" in str(exc).lower():
                return
            raise

    def _ensure_feedback_schema(self, con: sqlite3.Connection) -> None:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_feedback (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER REFERENCES engagements(id),
                model         TEXT    NOT NULL DEFAULT 'qwen2.5-1.5b',
                prompt_hash   TEXT,
                response_hash TEXT,
                quality_score REAL,
                validator_ok  INTEGER NOT NULL DEFAULT 0,
                generated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self._safe_add_column(con, "ALTER TABLE llm_feedback ADD COLUMN correction_loops INTEGER DEFAULT 0")
        self._safe_add_column(con, "ALTER TABLE llm_feedback ADD COLUMN feedback_text TEXT")
        self._safe_add_column(con, "ALTER TABLE llm_feedback ADD COLUMN narrative_coherence_score REAL")
        self._safe_add_column(con, "ALTER TABLE llm_feedback ADD COLUMN opsec_violation_count INTEGER DEFAULT 0")
        self._safe_add_column(con, "ALTER TABLE llm_feedback ADD COLUMN hallucination_score REAL")
        self._safe_add_column(con, "ALTER TABLE llm_feedback ADD COLUMN factual_accuracy_score REAL")
        self._safe_add_column(con, "ALTER TABLE llm_feedback ADD COLUMN engagement_context_relevance REAL")
        self._safe_add_column(con, "ALTER TABLE llm_feedback ADD COLUMN final_approval BOOLEAN DEFAULT FALSE")
        self._safe_add_column(con, "ALTER TABLE llm_feedback ADD COLUMN validation_timestamp TIMESTAMP")
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_validation_rules (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name         TEXT    NOT NULL UNIQUE,
                rule_type         TEXT    NOT NULL CHECK (rule_type IN ('opsec','factual','coherence','relevance')),
                severity          TEXT    NOT NULL DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
                pattern           TEXT    NOT NULL,
                description       TEXT,
                remediation_hint  TEXT,
                enabled           INTEGER NOT NULL DEFAULT 1,
                created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

    # ------------------------------------------------------------------

    def _ensure_model_loaded(self, *, allow_auto_local: bool = False) -> None:
        # Provider path: skip llama_cpp entirely if a non-llama_cpp provider
        # was requested. Provider is loaded on first inference.
        if (
            self._provider_name
            and self._provider_name != "llama_cpp"
            and not allow_auto_local
        ):
            return

        if self._llm is not None:
            return
        if not self._model_path.exists():
            raise ModelNotFoundError(
                f"GGUF model not found: {self._model_path}. "
                f"Download Qwen2.5-1.5B-Instruct-Q4_K_M.gguf to "
                f"{DEFAULT_MODEL_DIR} or set --model-path. "
                f"Alternatively, pass --provider <name> to route through a "
                f"cloud model (claude_code, gemini_cli, codex_cli, "
                f"bedrock_anthropic, openai_compatible)."
            )
        llama_cls = Llama
        if llama_cls is None:
            raise ImportError(
                "llama-cpp-python is not installed. "
                "Run: pip install llama-cpp-python==0.3.8"
            )

        logger.info("Loading model from %s ...", self._model_path)
        self._llm = llama_cls(
            model_path = str(self._model_path),
            n_ctx      = self._n_ctx,
            n_threads  = self._n_threads,
            verbose    = False,
        )
        logger.info("Model loaded.")

    def _ensure_provider_loaded(self) -> None:
        """Instantiate the LLMProvider on first use.

        Handles seven paths:
        ``llama_cpp`` (local Qwen — falls through to _ensure_model_loaded),
        ``kiro_cli`` (Kiro CLI subscription — usually the highest-quality
        default when kiro-cli is on PATH),
        ``claude_code`` / ``codex_cli`` / ``gemini_cli`` (subscription CLIs),
        ``bedrock_anthropic`` (AWS creds), and
        ``openai_compatible`` (any OpenAI-shaped endpoint).

        The special value ``auto`` builds a FallbackChainProvider that
        tries configured providers in env-driven order
        (``FORGE_LLM_CASCADE_ORDER`` or ``LLM_CASCADE_ORDER``). If no
        cloud provider loads, callers can still fall back to the local
        ``llama_cpp`` path before the deterministic template.

        For ``openai_compatible``, config is sourced from env vars:
            FORGE_OPENAI_BASE_URL, FORGE_OPENAI_MODEL, FORGE_OPENAI_API_KEY
        """
        if self._llm_provider is not None:
            return
        name = self._provider_name

        try:
            if name == "kiro_cli":
                from forge.providers.kiro_cli import KiroCliProvider  # noqa: PLC0415
                self._llm_provider = KiroCliProvider()
            elif name == "claude_code":
                from forge.providers.claude_code import ClaudeCodeProvider  # noqa: PLC0415
                self._llm_provider = ClaudeCodeProvider()
            elif name == "codex_cli":
                from forge.providers.codex_cli import CodexCliProvider  # noqa: PLC0415
                self._llm_provider = CodexCliProvider()
            elif name == "gemini_cli":
                from forge.providers.gemini_cli import GeminiCliProvider  # noqa: PLC0415
                self._llm_provider = GeminiCliProvider()
            elif name == "bedrock_anthropic":
                from forge.providers.bedrock_anthropic import BedrockAnthropicProvider  # noqa: PLC0415
                self._llm_provider = BedrockAnthropicProvider()
            elif name == "openai_compatible":
                import os as _os  # noqa: PLC0415
                from forge.providers.openai_compatible import OpenAICompatibleProvider  # noqa: PLC0415
                base_url = _os.environ.get("FORGE_OPENAI_BASE_URL")
                model = _os.environ.get("FORGE_OPENAI_MODEL")
                api_key = _os.environ.get("FORGE_OPENAI_API_KEY")
                if not (base_url and model):
                    raise ValueError(
                        "FORGE_OPENAI_BASE_URL and FORGE_OPENAI_MODEL "
                        "must be set for --provider openai_compatible"
                    )
                self._llm_provider = OpenAICompatibleProvider(
                    endpoint=base_url, model=model, api_key=api_key or ""
                )
            elif name == "auto":
                self._llm_provider = self._build_auto_chain()
            else:
                raise ValueError(
                    f"Unknown provider '{name}'. Supported: "
                    "llama_cpp | auto | kiro_cli | claude_code | codex_cli | "
                    "gemini_cli | bedrock_anthropic | openai_compatible"
                )
        except ImportError as exc:
            raise ImportError(
                f"Provider '{name}' import failed: {exc}. "
                f"Ensure its dependencies are installed."
            ) from exc
        logger.info("LLM provider loaded: %s", name)

    def _build_auto_chain(self):
        """Assemble a FallbackChainProvider from all detected providers.

        Provider order is driven by ``FORGE_LLM_CASCADE_ORDER`` or
        ``LLM_CASCADE_ORDER`` when present; otherwise the built-in
        default order is used. Each detection is best-effort and
        unavailable providers are skipped. Local ``llama_cpp`` and the
        deterministic template are handled outside this cloud-only chain.
        """
        import shutil as _sh  # noqa: PLC0415
        from forge.providers.fallback import FallbackChainProvider  # noqa: PLC0415

        chain: list = []
        for provider_name in self._configured_auto_cascade_order():
            if provider_name in {"llama_cpp", "template"}:
                continue
            try:
                if provider_name == "kiro_cli":
                    if not (_sh.which("kiro-cli") or _sh.which("kiro-cli.exe")):
                        continue
                    from forge.providers.kiro_cli import KiroCliProvider  # noqa: PLC0415
                    chain.append(("kiro_cli", KiroCliProvider()))
                elif provider_name == "claude_code":
                    if not (_sh.which("claude") or _sh.which("claude.cmd")):
                        continue
                    from forge.providers.claude_code import ClaudeCodeProvider  # noqa: PLC0415
                    chain.append(("claude_code", ClaudeCodeProvider()))
                elif provider_name == "openai_compatible":
                    if not (os.environ.get("FORGE_OPENAI_BASE_URL") and os.environ.get("FORGE_OPENAI_MODEL")):
                        continue
                    from forge.providers.openai_compatible import OpenAICompatibleProvider  # noqa: PLC0415
                    chain.append(
                        (
                            "openai_compatible",
                            OpenAICompatibleProvider(
                                endpoint=os.environ["FORGE_OPENAI_BASE_URL"],
                                model=os.environ["FORGE_OPENAI_MODEL"],
                                api_key=os.environ.get("FORGE_OPENAI_API_KEY", ""),
                            ),
                        )
                    )
                elif provider_name == "codex_cli":
                    if not (_sh.which("codex") or _sh.which("codex.cmd")):
                        continue
                    from forge.providers.codex_cli import CodexCliProvider  # noqa: PLC0415
                    chain.append(("codex_cli", CodexCliProvider()))
                elif provider_name == "gemini_cli":
                    if not (_sh.which("gemini") or _sh.which("gemini.cmd")):
                        continue
                    from forge.providers.gemini_cli import GeminiCliProvider  # noqa: PLC0415
                    chain.append(("gemini_cli", GeminiCliProvider()))
                elif provider_name == "bedrock_anthropic":
                    if not (os.environ.get("AWS_REGION") or os.environ.get("AWS_PROFILE")):
                        continue
                    from forge.providers.bedrock_anthropic import BedrockAnthropicProvider  # noqa: PLC0415
                    chain.append(("bedrock_anthropic", BedrockAnthropicProvider()))
            except Exception as exc:  # noqa: BLE001
                logger.debug("%s skipped: %s", provider_name, exc)

        if not chain:
            raise ValueError(
                "--provider auto: no configured cloud LLM providers detected. "
                "Set FORGE_LLM_CASCADE_ORDER or LLM_CASCADE_ORDER to control order, "
                "install one of: kiro-cli, claude, codex, gemini; or set "
                "FORGE_OPENAI_BASE_URL/MODEL/API_KEY; or set AWS creds."
            )

        logger.info(
            "LLM provider loaded: auto -> %s (fallback chain)",
            " -> ".join(name for name, _ in chain),
        )
        # Wide per-call timeout: an LLM CLI can take 60-120s for a long
        # report. Circuit breaker: 60s cooldown after a hard failure.
        return FallbackChainProvider(
            chain, per_call_timeout=300.0, cooldown_seconds=60.0,
        )

    def _infer(self, prompt: str) -> str:
        """Dispatch inference to the configured LLM backend.

        - ``provider == "llama_cpp"`` (or unset): local llama-cpp-python via
          ``_infer_via_llama_cpp`` (existing behaviour).
        - Any other provider: ``_infer_via_provider`` shells out through the
          registered ``LLMProvider`` implementation.
        """
        if self._provider_name == "auto" and self._llm_provider is None and self._llm is not None:
            return self._infer_via_llama_cpp(prompt)
        if self._provider_name and self._provider_name != "llama_cpp":
            return self._infer_via_provider(prompt)
        return self._infer_via_llama_cpp(prompt)

    def _infer_via_provider(self, prompt: str) -> str:
        """Run inference through an :class:`LLMProvider` (cloud or CLI)."""
        import asyncio  # noqa: PLC0415
        from forge.providers.base import CompletionRequest  # noqa: PLC0415

        self._ensure_provider_loaded()
        assert self._llm_provider is not None

        SYSTEM_DIRECTIVE = (
            "You are a professional authorized security assessment report writer. "
            "Write formal, factual prose. "
            "Never reproduce credential plaintexts, paste URLs, or raw payloads. "
            "Reference sensitive data by type and count only. "
            "Structure the report with the exact section headings provided. "
            "If an Ongoing Intelligence section is present, reference monitoring dates explicitly. "
            "Write in formal British English."
        )
        req = CompletionRequest(
            prompt=prompt,
            max_tokens=MAX_COMPLETION_TOK,
            temperature=self._temperature,
            system=SYSTEM_DIRECTIVE,
        )
        response = asyncio.run(self._llm_provider.complete(req))
        return response.text

    def _infer_via_llama_cpp(self, prompt: str) -> str:
        """Call llama_cpp with the assembled prompt and return raw text."""
        assert self._llm is not None

        SYSTEM_DIRECTIVE = (
            "You are a professional authorized security assessment report writer. "
            "Write formal, factual prose. "
            "Never reproduce credential plaintexts, paste URLs, or raw payloads. "
            "Reference sensitive data by type and count only. "
            "Structure the report with the exact section headings provided. "
            "If an Ongoing Intelligence section is present, reference monitoring dates explicitly. "
            "Write in formal British English."
        )

        output = self._llm.create_chat_completion(
            messages=[
                {"role": "system", "content": SYSTEM_DIRECTIVE},
                {"role": "user",   "content": prompt},
            ],
            max_tokens  = MAX_COMPLETION_TOK,
            temperature = self._temperature,
            top_p       = 0.9,
            repeat_penalty = 1.1,
        )
        return output["choices"][0]["message"]["content"]

    def _render_skeleton(self, ctx: ReportContext) -> str:
        """Deterministic factual template report — no LLM required.

        Used in three scenarios:
          1. Explicit ``--provider template`` (fastest, most reliable).
          2. ``--provider auto`` when NO cloud provider loads AND local
             llama.cpp GGUF is absent (last-resort fallback so the
             pipeline never fails silently).
          3. ``dry_run=True`` for smoke tests without an LLM call.

        The output is a proper Markdown authorized security assessment report grounded strictly
        in the engagement DB. No hallucinated content, no OPSEC leaks
        (per-host IPs and service versions are aggregated by class).
        Prose is terse and factual — a cloud LLM produces more flowing
        narrative, but this template beats "5 KB of hallucinated fluff"
        for accuracy.
        """
        from datetime import datetime as _dt, timezone as _tz  # noqa: PLC0415

        ts = _dt.now(tz=_tz.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Aggregate host OS counts (avoids leaking individual IPs)
        os_counts: dict[str, int] = {}
        for h in ctx.recon.hosts:
            os_family = str(h.get("os_guess") or "unknown").lower()
            os_counts[os_family] = os_counts.get(os_family, 0) + 1

        # Aggregate service counts
        svc_counts: dict[str, int] = {}
        for p in ctx.recon.open_ports:
            svc = str(p.get("service") or "unknown").lower()
            svc_counts[svc] = svc_counts.get(svc, 0) + 1

        os_table = (
            "\n".join(f"| {name} | {n} |" for name, n in sorted(os_counts.items()))
            or "| (none) | 0 |"
        )
        svc_table = (
            "\n".join(f"| {name} | {n} |" for name, n in sorted(svc_counts.items()))
            or "| (none) | 0 |"
        )
        seed_type_summary = (
            ", ".join(
                f"{seed_type}={count}"
                for seed_type, count in sorted(ctx.seed_summary.type_counts.items())
            )
            or "none"
        )

        def _md_cell(value: object) -> str:
            return str(value or "").replace("|", "\\|").replace("\n", " ").strip()

        seed_rows = []
        for seed in ctx.seed_summary.seeds[:25]:
            seed_rows.append(
                "| "
                + " | ".join(
                    [
                        _md_cell(seed.get("type")),
                        f"`{_md_cell(seed.get('value'))}`",
                        _md_cell(seed.get("source")),
                        _md_cell(seed.get("status")),
                        _md_cell(seed.get("depth")),
                        _md_cell(seed.get("confidence")),
                    ]
                )
                + " |"
            )
        seed_table = (
            "| Type | Value | Source | Status | Depth | Confidence |\n"
            "|---|---|---|---|---|---|\n"
            + "\n".join(seed_rows)
            if seed_rows
            else "_No engagement seeds were recorded in this reporting window._"
        )
        relation_rows = []
        for relation in ctx.seed_summary.relations[:25]:
            relation_rows.append(
                "| "
                + " | ".join(
                    [
                        f"`{_md_cell(relation.get('source_value'))}`",
                        _md_cell(relation.get("relation_type")),
                        f"`{_md_cell(relation.get('target_value'))}`",
                        _md_cell(relation.get("confidence")),
                        _md_cell(relation.get("evidence")),
                    ]
                )
                + " |"
            )
        relation_table = (
            "| Source | Relation | Target | Confidence | Evidence |\n"
            "|---|---|---|---|---|\n"
            + "\n".join(relation_rows)
            if relation_rows
            else "_No seed cross-reference examples were recorded in this reporting window._"
        )
        archive_rows = []
        for item in ctx.recon.archive_urls[:25]:
            archive_rows.append(
                "| "
                + " | ".join(
                    [
                        f"`{_md_cell(item.get('url'))}`",
                        _md_cell(", ".join(str(source) for source in item.get("sources", []) or [])),
                        _md_cell(item.get("root_domain")),
                        _md_cell(item.get("title")),
                    ]
                )
                + " |"
            )
        archive_table = (
            "| URL | Source | Root domain | Title |\n"
            "|---|---|---|---|\n"
            + "\n".join(archive_rows)
            if archive_rows
            else "_No archive URL provenance was recorded in this reporting window._"
        )

        # Deterministic fallback should enumerate every validated finding so
        # the last-resort report does not silently drop confirmed exposures.
        exploits_section = ""
        detailed_findings_section = ""
        if ctx.exploits.exploited:
            rows = []
            for finding in ctx.exploits.exploited:
                cve = finding.get("cve_id") or "—"
                sev = finding.get("severity") or "—"
                title = finding.get("title") or "—"
                rows.append(f"| {cve} | {sev} | {title} |")
            exploits_section = (
                "| CVE | Severity | Title |\n"
                "|---|---|---|\n"
                + "\n".join(rows)
                + "\n"
            )
            detail_blocks = []
            for finding in ctx.exploits.exploited:
                title = str(finding.get("title") or finding.get("cve_id") or "Validated finding").strip()
                severity = str(finding.get("severity") or "UNKNOWN").strip()
                asset = (
                    str(finding.get("target_url") or "").strip()
                    or str(finding.get("resource_id") or "").strip()
                    or str(finding.get("cve_id") or "").strip()
                    or "Not recorded"
                )
                description = (
                    str(finding.get("description") or "").strip()
                    or "Deterministic validation confirmed this finding from structured engagement data."
                )
                evidence = str(finding.get("evidence") or "").strip() or "Not recorded"
                remediation = (
                    str(finding.get("remediation_cli") or "").strip()
                    or "Review the validated exposure and remediate the affected asset using the associated deterministic control guidance."
                )
                provider = str(finding.get("cloud_provider") or "").strip()
                provider_line = f"- **Provider**: {provider}\n" if provider else ""
                validation_status = str(finding.get("validation_status") or "").strip()
                validation_method = str(finding.get("validation_method") or "").strip()
                validation_http_status = str(finding.get("validation_http_status") or "").strip()
                validation_notes = str(finding.get("validation_notes") or "").strip()
                validation_parts = []
                if validation_status:
                    validation_parts.append(validation_status)
                if validation_method:
                    validation_parts.append(f"via `{validation_method}`")
                if validation_http_status:
                    validation_parts.append(f"HTTP {validation_http_status}")
                validation_line = (
                    f"- **Validation**: {' '.join(validation_parts)}"
                    if validation_parts
                    else ""
                )
                validation_notes_line = (
                    f"- **Validation notes**: {validation_notes}"
                    if validation_notes
                    else ""
                )
                optional_validation_lines = [
                    line
                    for line in (validation_line, validation_notes_line)
                    if line
                ]
                detail_blocks.append(
                    "\n".join(
                        [
                            f"#### [{severity}] {title}",
                            provider_line + f"- **Asset**: {asset}",
                            f"- **Description**: {description}",
                            *optional_validation_lines,
                            f"- **Evidence**: {evidence}",
                            f"- **Recommendation**: {remediation}",
                        ]
                    )
                )
            detailed_findings_section = "\n\n".join(detail_blocks)
        else:
            exploits_section = (
                "_No validated finding paths in this window. "
                "Correlation surfaced candidates for future engagement._\n"
            )

        # Evidence handling summary
        pex = ctx.post_exploitation
        evidence_categories = ", ".join(sorted(pex.artifact_summary)[:6]) or "none"

        return "\n".join([
            "# Authorized Security Assessment Report",
            "",
            f"**Engagement:** {ctx.engagement_name} (ID {ctx.engagement_id})",
            f"**Operator:** {ctx.operator}",
            f"**Overall risk:** {ctx.overall_risk}",
            f"**Generated (template mode, no LLM):** {ts}",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"This engagement was conducted within the authorised scope "
            f"`{', '.join(ctx.scope) if ctx.scope else '<none>'}`. "
            f"Reconnaissance identified {len(ctx.recon.hosts)} live host(s) "
            f"exposing {len(ctx.recon.open_ports)} open service(s) and "
            f"{len(ctx.recon.subdomains)} subdomain(s). Open-source "
            f"intelligence yielded {ctx.osint.emails_found} email address(es), "
            f"{ctx.osint.credential_hashes} credential hash(es), "
            f"{ctx.osint.email_intelligence_records} email-intelligence record(s), "
            f"{ctx.osint.registered_account_count} registered-account hit(s), "
            f"{len(ctx.osint.breach_sources)} breach-corpus reference(s), and "
            f"{ctx.osint.reputation_alert_count} reputation alert(s). "
            f"Vulnerability and exposure correlation produced "
            f"{ctx.exploits.critical_count} critical, {ctx.exploits.high_count} "
            f"high, and {ctx.exploits.medium_count} medium-severity finding(s) "
            f"across {ctx.exploits.finding_count} validated finding(s) and "
            f"{ctx.exploits.cve_count} distinct CVE reference(s). "
            "Evidence handling remained bounded to scoped discovery, static "
            "artifact analysis, and non-destructive validation records.",
            "",
            "## 2. Engagement Scope & Methodology",
            "",
            f"**Scope:** {', '.join(ctx.scope) if ctx.scope else '<undefined>'}",
            f"**Start:** {ctx.start_date or '<not recorded>'}",
            f"**End:** {ctx.end_date or '<not recorded>'}",
            f"**Operator:** {ctx.operator}",
            "",
            "The engagement followed the standard FORGE Toolkit phased "
            "methodology: Phase 0 (knowledge-base ETL), Phase 1 "
            "(reconnaissance), Phase 2 (OSINT + credential intelligence), "
            "Phase 3 (scope and validation preparation), Phase 4 "
            "(vulnerability and exposure correlation), and Phase 6 "
            "(deterministic reporting).",
            "",
            "## 3. Reconnaissance Findings",
            "",
            f"**Hosts discovered:** {len(ctx.recon.hosts)}  \n"
            f"**Open services:** {len(ctx.recon.open_ports)}  \n"
            f"**Subdomains enumerated:** {len(ctx.recon.subdomains)}",
            "",
            "### 3.1 Host operating-system distribution",
            "",
            "| OS family | Host count |",
            "|---|---|",
            os_table,
            "",
            "### 3.2 Service class distribution",
            "",
            "| Service | Instance count |",
            "|---|---|",
            svc_table,
            "",
            "_Per-host identifiers, port assignments and version indicators "
            "are retained in the engagement's controlled operational records "
            "and are not reproduced in this document._",
            "",
            "### 3.3 Passive archive URL provenance",
            "",
            archive_table,
            "",
            "## 4. OSINT & Credential Intelligence",
            "",
            f"**Emails harvested:** {ctx.osint.emails_found}  \n"
            f"**Credential hashes:** {ctx.osint.credential_hashes} "
            "(count only; plaintext never reproduced)  \n"
            f"**Email-intelligence records:** {ctx.osint.email_intelligence_records}  \n"
            f"**Registered-account hits:** {ctx.osint.registered_account_count} "
            f"across {len(ctx.osint.registered_account_services)} service(s)  \n"
            f"**Account-existence rate limits:** {ctx.osint.account_existence_rate_limited}  \n"
            f"**Intelligence sources:** "
            f"{', '.join(ctx.osint.intelligence_sources) if ctx.osint.intelligence_sources else 'None'}  \n"
            f"**Breached emails:** {ctx.osint.breached_email_count}  \n"
            f"**Reputation alerts:** {ctx.osint.reputation_alert_count}  \n"
            f"**Paste alerts:** {ctx.osint.paste_alert_count}  \n"
            f"**Breach corpora referenced:** "
            f"{len(ctx.osint.breach_sources)}  \n"
            f"**Exposed-key findings:** {ctx.osint.key_findings_count}",
            "",
            "### 4.1 Engagement Seeds & Entity Summary",
            "",
            f"**Tracked seeds:** {len(ctx.seed_summary.seeds)}  \n"
            f"**Seed types:** {seed_type_summary}  \n"
            f"**Cross-reference relations:** {ctx.seed_summary.relation_count}",
            "",
            seed_table,
            "",
            "#### Recursive Discovery & Cross-Reference Evidence",
            "",
            relation_table,
            "",
            "## 5. Vulnerability & Exposure Correlation",
            "",
            f"**Critical:** {ctx.exploits.critical_count}  \n"
            f"**High:** {ctx.exploits.high_count}  \n"
            f"**Medium:** {ctx.exploits.medium_count}  \n"
            f"**Validated findings:** {ctx.exploits.finding_count}  \n"
            f"**Distinct CVE references:** {ctx.exploits.cve_count}",
            "",
            "### 5.1 Validated findings",
            "",
            exploits_section,
            "### 5.2 Finding details",
            "",
            detailed_findings_section or "_No detailed validated findings in this window._",
            "",
            "",
            "## 6. Validation Boundaries & Evidence Handling",
            "",
            f"**Controlled evidence categories:** {evidence_categories}  \n"
            f"**Artifact family buckets:** {len(pex.artifact_summary)}  \n"
            f"**Artifact type buckets:** {sum(len(rows) for rows in pex.artifact_type_summary.values())}  \n"
            "**Validation boundary:** Reported findings are limited to scoped discovery, "
            "static artifact analysis, and non-destructive proof records. "
            "Unvalidated, dead, placeholder, or low-signal evidence remains analyst "
            "inventory unless deterministic report gates classify it as reportable.",
            "",
            "## 7. Risk Ratings & Remediation Recommendations",
            "",
            f"**Overall engagement risk:** {ctx.overall_risk}",
            "",
            "**General recommendations (priority-ranked):**",
            "",
            "1. Patch every CVE identified in Section 5 above, "
            "starting with critical-severity items.",
            "2. Enforce network segmentation between administrative and "
            "user-facing service classes (see Section 3.2).",
            "3. Review authentication surface for any service classes "
            "exposing administrative capability (SSH, RDP, SMB, "
            "management web UIs) — enforce MFA where practical.",
            "4. Schedule an authenticated vulnerability assessment to "
            "surface patch-level exposures not visible through "
            "unauthenticated reconnaissance.",
            "5. If deeper active validation is required, document separate "
            "rules of engagement, scope limits, pacing, and approval evidence "
            "before expanding beyond the current non-destructive workflow.",
            "",
            "---",
            "",
            "## 8. Timeline of Operator Actions",
            "",
            self._render_audit_timeline(ctx),
            "",
            "---",
            "",
            f"_Report generated by FORGE Toolkit template renderer "
            f"(no LLM). Engagement DB: `{self._db_path.name}`._",
            "",
        ])

    def _render_audit_timeline(self, ctx: ReportContext) -> str:
        """Render engagement audit_log rows as a chronological timeline.

        Turns the hash-chained receipt (populated by _cli_audit and the
        per-module _audit helpers) into part of the deliverable. If the
        table is empty or missing, returns a neutral placeholder line.
        """
        try:
            con = sqlite3.connect(
                f"file:{self._db_path.as_posix()}?mode=ro", uri=True,
            )
            try:
                rows = con.execute(
                    """
                    SELECT logged_at, phase, module, action, target, result, operator
                    FROM audit_log
                    WHERE engagement_id = ?
                    ORDER BY id ASC
                    """,
                    (ctx.engagement_id,),
                ).fetchall()
            except sqlite3.OperationalError:
                return (
                    "_Audit log unavailable — this engagement's DB predates "
                    "the audit_log schema. Future engagements will render "
                    "a chronological action list here._"
                )
            finally:
                con.close()
        except sqlite3.Error as exc:
            return f"_Audit log query failed: {exc}._"

        if not rows:
            return (
                "_No operator actions recorded for this engagement. The "
                "audit_log table is present but empty — either the "
                "engagement predates the tamper-evident logging feature, "
                "or the operator interacted with the DB directly rather "
                "than via `forge`._"
            )

        def _esc(s: object) -> str:
            return str(s if s is not None else "—").replace("|", "\\|")

        lines = [
            "| # | Timestamp (UTC) | Phase | Module | Action | Result | Operator |",
            "|---|---|---|---|---|---|---|",
        ]
        # Cap at 40 rows to keep the report a reasonable size.
        display_rows = rows[:40]
        for i, r in enumerate(display_rows, start=1):
            logged_at, phase, module, action, target, result, operator = r
            result_short = (result or "")[:60]
            if result and len(result) > 60:
                result_short += "…"
            lines.append(
                f"| {i} | {_esc(logged_at)} | {_esc(phase)} | "
                f"{_esc(module)} | {_esc(action)} | "
                f"{_esc(result_short)} | {_esc(operator)} |"
            )
        if len(rows) > len(display_rows):
            lines.append("")
            lines.append(
                f"_Timeline truncated to first {len(display_rows)} of "
                f"{len(rows)} rows. Full audit trail available via "
                f"`SELECT * FROM audit_log WHERE engagement_id="
                f"{ctx.engagement_id}` or through the hash-chain verifier "
                f"(`forge.audit.verifier`)._"
            )
        return "\n".join(lines)

    def _write_report(
        self, ctx: ReportContext, raw_text: str, dry_run: bool = False
    ) -> Path:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        ts      = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S")
        stem    = f"engagement_{ctx.engagement_id}_report_{ts}"
        out     = self._output_dir / f"{stem}.md"

        # Skip the interactive confirm when the caller opted in via
        # assume_yes OR when we detect no attached terminal. The prompt_toolkit
        # backend behind questionary requires a real console screen buffer on
        # Windows and raises NoConsoleScreenBufferError under any redirected-
        # stdio invocation (CI, subprocess, pytest, Tee-Object).
        skip_confirm = self._assume_yes or not sys.stdin.isatty()
        if skip_confirm:
            logger.info(
                "Auto-confirming write to %s (assume_yes=%s, stdin_isatty=%s)",
                out, self._assume_yes, sys.stdin.isatty(),
            )
        else:
            confirmed_prompt = questionary.confirm(f"Write report to {out}?")
            confirmed = (
                confirmed_prompt.ask()
                if hasattr(confirmed_prompt, "ask")
                else bool(confirmed_prompt)
            )
            if not confirmed:
                raise RuntimeError("Operator cancelled report write.")

        markdown_text = self._decorate_report(ctx, raw_text, dry_run)
        out.write_text(markdown_text, encoding="utf-8")
        self._write_companion_exports(
            ctx,
            out,
            markdown_text,
            dry_run=dry_run,
        )
        logger.info("Report written to %s", out)
        return out


def synthesise(
    engagement_id: str | int,
    output_path: str | None = None,
    assume_yes: bool = False,
    provider: str | None = None,
    max_correction_loops: int | None = None,
) -> Path:
    from forge.config import ForgeConfig

    cfg = ForgeConfig.load()
    eid = int(engagement_id)
    db_path = cfg.engagement_db_path(str(engagement_id))

    output_target = Path(output_path) if output_path else None
    output_dir = (
        output_target
        if output_target and output_target.suffix == ""
        else output_target.parent if output_target else Path(".")
    )

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=output_dir,
        assume_yes=assume_yes,
        provider=provider,
        max_correction_loops=max_correction_loops,
    )
    generated = synthesizer.generate(engagement_id=eid)

    if output_target and output_target.suffix.lower() in {".md", ".json", ".pdf"}:
        output_target.parent.mkdir(parents=True, exist_ok=True)
        generated_family: dict[str, Path] = {}
        if generated.suffix.lower() == ".md":
            generated_family = {
                ".md": generated,
                ".json": generated.with_suffix(".json"),
                ".pdf": generated.with_suffix(".pdf"),
                ".csv": generated.with_suffix(".csv"),
            }
        else:
            generated_family[generated.suffix.lower()] = generated
            sibling_json = generated.with_suffix(".json")
            sibling_csv = generated.with_suffix(".csv")
            if sibling_json.exists():
                generated_family[".json"] = sibling_json
            if sibling_csv.exists():
                generated_family[".csv"] = sibling_csv

        target_root = output_target.with_suffix("")
        target_family = {
            suffix: target_root.with_suffix(suffix)
            for suffix in generated_family
        }
        for suffix, source_path in generated_family.items():
            if not source_path.exists():
                continue
            destination = target_family[suffix]
            if source_path.resolve() == destination.resolve():
                continue
            shutil.copyfile(source_path, destination)
        if ".md" in generated_family and generated_family[".md"].resolve() != target_family[".md"].resolve():
            for source_path in generated_family.values():
                source_path.unlink(missing_ok=True)
        requested_suffix = output_target.suffix.lower()
        if requested_suffix in target_family and target_family[requested_suffix].exists():
            return target_family[requested_suffix]
        if ".json" in target_family and target_family[".json"].exists():
            return target_family[".json"]
        return next(iter(target_family.values()))

    return generated
