"""
forge/phase4/mobile_config_parse.py
Firebase Project ID Extraction from APK / AAB / IPA — Module 4-F.

Passive, offline analysis. No network activity. No scope gate required.
Extracts Firebase project identifiers, API keys, RTDB URLs, and storage-bucket
references from Android
Android APK/AAB and iOS IPA application bundles.

Sources:
  APK primary   — google-services.json  (project_info.project_id, storage_bucket, client[].api_key)
  APK fallback  — res/values/strings.xml regex for *.firebaseio.com URLs
  IPA primary   — GoogleService-Info.plist (PROJECT_ID, API_KEY, DATABASE_URL, STORAGE_BUCKET)
  IPA fallback  — all .plist files regex for *.firebaseio.com URLs

OPSEC (PRD §12.7.3):
  - API keys age-encrypted at extraction time; never written as plaintext.
  - cloud_assets.identifier stores project_id only (not key).
  - --output-json file registered with cleanup.py immediately after creation.
  - No external calls at any point (purely stdlib: zipfile + plistlib + json).
"""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import plistlib
import re
import sqlite3
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Optional

import httpx
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)

_RTDB_URL_RE = re.compile(
    r"https?://([a-zA-Z0-9\-]+)\.firebaseio\.com",
    re.IGNORECASE,
)
_SUPABASE_URL_RE = re.compile(r"https://([a-z0-9\-]+)\.supabase\.co", re.IGNORECASE)
_SUPABASE_KEY_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)", re.IGNORECASE
)
_MOBILE_CONFIG_PARSE_MAX_WORKERS = 4
_ANDROID_DIRECT_BUNDLE_SUFFIXES = {".apk", ".aab"}
_ANDROID_ARCHIVE_BUNDLE_SUFFIXES = {".xapk", ".apkm", ".apks"}
_ANDROID_BUNDLE_SUFFIXES = _ANDROID_DIRECT_BUNDLE_SUFFIXES | _ANDROID_ARCHIVE_BUNDLE_SUFFIXES
_NESTED_ANDROID_BUNDLE_MAX_DEPTH = 3


# ── Data model ─────────────────────────────────────────────────────────────────


@dataclass
class FirebaseProject:
    project_id: str
    api_key_enc: Optional[str]  # age-encrypted; None if not found
    rtdb_url: Optional[str]
    bundle_id: Optional[str]  # iOS bundle ID if available
    source_file: str
    extract_path: str  # internal path within the archive
    storage_bucket: Optional[str] = None


@dataclass
class SupabaseConfig:
    project_ref: str
    project_url: str
    anon_key: str
    source_file: str
    extract_path: str


# ── Extractor ──────────────────────────────────────────────────────────────────


class FirebaseExtractor:
    """
    Passive APK/IPA decompiler for Firebase configuration extraction.

    Usage:
        extractor = FirebaseExtractor(age_pubkey="age1...")
        projects  = extractor.extract_apk(Path("app.apk"))
        projects += extractor.extract_apk(Path("app.aab"))
        projects += extractor.extract_apk(Path("bundle.xapk"))
        projects += extractor.extract_ipa(Path("app.ipa"))
        extractor.store(projects, db_path, engagement_id=1)
    """

    def __init__(self, age_pubkey: Optional[str] = None) -> None:
        self._age_pubkey = age_pubkey

    # ── APK extraction ─────────────────────────────────────────────────────────

    def extract_apk(self, apk_path: Path) -> list[FirebaseProject]:
        """Extract Firebase config from an Android APK/AAB/XAPK/APKM/APKS file."""
        projects: list[FirebaseProject] = []
        if not apk_path.exists():
            _LOG.error("Android bundle not found: %s", apk_path)
            return projects

        try:
            with zipfile.ZipFile(apk_path) as zf:
                projects.extend(
                    self._extract_android_bundle_projects_from_zip(
                        zf,
                        apk_path,
                        nested_prefix="",
                        depth=0,
                    )
                )
        except zipfile.BadZipFile:
            _LOG.error("Not a valid Android bundle/ZIP: %s", apk_path)
        except Exception as exc:
            _LOG.error("Android bundle extraction error (%s): %s", apk_path, exc)

        projects = self._dedupe_firebase_projects(projects)
        _LOG.info("Android bundle %s: %d Firebase project(s) found", apk_path.name, len(projects))
        return projects

    # ── IPA extraction ─────────────────────────────────────────────────────────

    def extract_ipa(self, ipa_path: Path) -> list[FirebaseProject]:
        """Extract Firebase config from an iOS IPA file."""
        projects: list[FirebaseProject] = []
        if not ipa_path.exists():
            _LOG.error("IPA not found: %s", ipa_path)
            return projects

        try:
            with zipfile.ZipFile(ipa_path) as zf:
                projects.extend(self._parse_googleservice_plist(zf, ipa_path))
                if not projects:
                    projects.extend(self._scan_plist_files(zf, ipa_path))
        except zipfile.BadZipFile:
            _LOG.error("Not a valid IPA/ZIP: %s", ipa_path)
        except Exception as exc:
            _LOG.error("IPA extraction error (%s): %s", ipa_path, exc)

        _LOG.info("IPA %s: %d Firebase project(s) found", ipa_path.name, len(projects))
        return projects

    # ── Storage ────────────────────────────────────────────────────────────────

    def store(
        self,
        projects: list[FirebaseProject],
        db_path: Path,
        engagement_id: int,
    ) -> int:
        """
        Write discovered projects to cloud_assets. Returns count inserted.
        API keys are never written to this table; only project identifiers.
        """
        if not projects:
            return 0
        con = direct_connect(db_path)
        self._ensure_schema(con)
        count = 0
        seen: set[str] = set()
        project_entries = self._phase4_ordered_batch(
            projects,
            self._firebase_store_entry,
            default_factory=lambda: None,
        )
        for project_entry in project_entries:
            if not isinstance(project_entry, dict):
                continue
            key = str(project_entry["store_key"])
            if key in seen:
                continue
            seen.add(key)
            con.execute(
                """INSERT OR IGNORE INTO cloud_assets
                   (engagement_id, asset_type, identifier, provider_identifier, source)
                   VALUES (?, 'firebase', ?, ?, 'firebase_extract')""",
                (engagement_id, project_entry["project_id"], project_entry["project_id"]),
            )
            if project_entry["storage_bucket"]:
                con.execute(
                    """INSERT OR IGNORE INTO cloud_assets
                       (engagement_id, asset_type, identifier, provider_identifier, source)
                       VALUES (?, 'gcs', ?, ?, 'firebase_extract_storage_bucket')""",
                    (
                        engagement_id,
                        project_entry["storage_bucket"],
                        project_entry["storage_bucket"],
                    ),
                )
            count += 1
        con.commit()
        con.close()
        _LOG.info("Stored %d Firebase project(s) to cloud_assets", count)
        return count

    @staticmethod
    def _firebase_store_entry(project: FirebaseProject) -> dict[str, str | None]:
        return {
            "store_key": f"{project.project_id}:{project.source_file}",
            "project_id": project.project_id,
            "storage_bucket": project.storage_bucket,
        }

    def emit_json(self, projects: list[FirebaseProject], output_path: Path) -> None:
        """
        Write structured JSON of all findings.
        API key values written as '<encrypted>' placeholder — never plaintext.
        """
        data = self._phase4_ordered_batch(
            projects,
            self._firebase_emit_json_row,
            default_factory=dict,
        )
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        _LOG.info("Firebase projects written to %s", output_path)
        self._register_cleanup(output_path)

    def emit_mobile_config_json(
        self,
        projects: list[FirebaseProject],
        supabase_configs: list[SupabaseConfig],
        output_path: Path,
    ) -> None:
        """Write combined Firebase + Supabase mobile-config findings without plaintext keys."""
        payload = {
            "firebase_projects": self._phase4_ordered_batch(
                projects,
                self._firebase_emit_mobile_config_row,
                default_factory=dict,
            ),
            "supabase_configs": self._phase4_ordered_batch(
                supabase_configs,
                self._supabase_emit_mobile_config_row,
                default_factory=dict,
            ),
        }
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        _LOG.info("Mobile config findings written to %s", output_path)
        self._register_cleanup(output_path)

    @staticmethod
    def _phase4_ordered_batch(
        items: list[Any],
        builder: Callable[[Any], Any],
        *,
        default_factory: Callable[[], Any],
    ) -> list[Any]:
        if not items:
            return []
        if len(items) == 1:
            return [builder(items[0])]
        bounded_workers = min(_MOBILE_CONFIG_PARSE_MAX_WORKERS, len(items))
        ordered_results: list[Any | None] = [None] * len(items)
        with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
            future_map = {executor.submit(builder, item): index for index, item in enumerate(items)}
            for future in as_completed(future_map):
                index = future_map[future]
                try:
                    ordered_results[index] = future.result()
                except Exception:  # noqa: BLE001
                    ordered_results[index] = default_factory()
        return [result if result is not None else default_factory() for result in ordered_results]

    @staticmethod
    def _firebase_emit_json_row(project: FirebaseProject) -> dict[str, Any]:
        return {
            "project_id": project.project_id,
            "api_key": "<age-encrypted>" if project.api_key_enc else None,
            "rtdb_url": project.rtdb_url,
            "bundle_id": project.bundle_id,
            "storage_bucket": project.storage_bucket,
            "source_file": project.source_file,
        }

    @staticmethod
    def _firebase_emit_mobile_config_row(project: FirebaseProject) -> dict[str, Any]:
        return {
            "project_id": project.project_id,
            "api_key": "<age-encrypted>" if project.api_key_enc else None,
            "rtdb_url": project.rtdb_url,
            "bundle_id": project.bundle_id,
            "storage_bucket": project.storage_bucket,
            "source_file": project.source_file,
            "extract_path": project.extract_path,
        }

    @staticmethod
    def _supabase_emit_mobile_config_row(config: SupabaseConfig) -> dict[str, Any]:
        return {
            "project_ref": config.project_ref,
            "project_url": config.project_url,
            "anon_key": "<age-encrypted>" if config.anon_key else None,
            "source_file": config.source_file,
            "extract_path": config.extract_path,
        }

    def extract_web_config(self, url: str) -> list[FirebaseProject]:
        projects: list[FirebaseProject] = []
        try:
            with httpx.Client(timeout=12, follow_redirects=True) as client:
                resp = client.get(url)
                if resp.status_code != 200:
                    return []
                html = resp.text
                snippets = re.findall(
                    r"firebase\.initializeApp\s*\(\s*(\{.*?\})\s*\)",
                    html,
                    re.IGNORECASE | re.DOTALL,
                )
                snippet_projects = self._phase4_ordered_batch(
                    snippets,
                    lambda snippet: self._firebase_web_snippet_project(snippet, source_url=url),
                    default_factory=lambda: None,
                )
                for snippet_project in snippet_projects:
                    if isinstance(snippet_project, FirebaseProject):
                        projects.append(snippet_project)
                for endpoint in (
                    "/__/firebase/init.json",
                    "/firebase-config.json",
                ):
                    try:
                        cfg = client.get(url.rstrip("/") + endpoint)
                    except Exception:
                        continue
                    if cfg.status_code != 200:
                        continue
                    try:
                        data = cfg.json()
                    except Exception:
                        continue
                    project_id = data.get("projectId")
                    api_key = data.get("apiKey")
                    if not isinstance(project_id, str) or not project_id:
                        continue
                    projects.append(
                        FirebaseProject(
                            project_id=project_id,
                            api_key_enc=self._encrypt(
                                api_key if isinstance(api_key, str) else None
                            ),
                            rtdb_url=data.get("databaseURL"),
                            bundle_id=None,
                            source_file=url,
                            extract_path=endpoint,
                            storage_bucket=self._normalize_storage_bucket(
                                data.get("storageBucket")
                            ),
                        )
                    )
        except Exception as exc:
            _LOG.error("Web config extraction error (%s): %s", url, exc)
        return self._dedupe_firebase_projects(projects)

    def _firebase_web_snippet_project(
        self,
        snippet: str,
        *,
        source_url: str,
    ) -> FirebaseProject | None:
        try:
            cleaned = snippet.replace("'", '"')
            data = json.loads(cleaned)
        except Exception:
            return None
        project_id = data.get("projectId")
        api_key = data.get("apiKey")
        if not isinstance(project_id, str) or not project_id:
            return None
        return FirebaseProject(
            project_id=project_id,
            api_key_enc=self._encrypt(api_key if isinstance(api_key, str) else None),
            rtdb_url=data.get("databaseURL"),
            bundle_id=None,
            source_file=source_url,
            extract_path=source_url,
            storage_bucket=self._normalize_storage_bucket(data.get("storageBucket")),
        )

    def store_supabase_configs(
        self,
        configs: list[SupabaseConfig],
        db_path: Path,
        engagement_id: int,
    ) -> int:
        """Persist Supabase project refs and redacted key findings for engagement workflows."""
        if not configs:
            return 0
        from forge.db.migrations import run_migrations
        from forge.db.schema import apply_schema

        con = direct_connect(db_path)
        apply_schema(con)
        run_migrations(con)
        self._ensure_engagement_row(con, engagement_id)
        count = 0
        seen: set[tuple[str, str, str]] = set()
        config_entries = self._phase4_ordered_batch(
            self._dedupe_supabase_configs(configs),
            self._supabase_store_entry,
            default_factory=lambda: None,
        )
        for config_entry in config_entries:
            if not isinstance(config_entry, dict):
                continue
            key = (
                str(config_entry["project_ref"]),
                str(config_entry["project_url"]),
                str(config_entry["source_file"]),
            )
            if key in seen:
                continue
            seen.add(key)
            con.execute(
                """INSERT OR IGNORE INTO cloud_assets
                   (engagement_id, asset_type, identifier, provider_identifier, source)
                   VALUES (?, 'supabase', ?, ?, 'mobile_config_parse')""",
                (engagement_id, config_entry["project_ref"], config_entry["project_ref"]),
            )
            con.execute(
                """INSERT OR IGNORE INTO key_scanner_findings
                   (engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc)
                   VALUES (?, ?, 'supabase', 'supabase_mobile_config', 'mobile_config_parse', ?, ?, ?, ?)""",
                (
                    engagement_id,
                    config_entry["project_ref"],
                    config_entry["source_file"],
                    config_entry["repo_name"],
                    config_entry["key_redacted"],
                    config_entry["key_enc"],
                ),
            )
            count += 1
        con.commit()
        con.close()
        _LOG.info("Stored %d Supabase config(s) to cloud_assets/key_scanner_findings", count)
        return count

    @staticmethod
    def _ensure_engagement_row(con: sqlite3.Connection, engagement_id: int) -> None:
        con.execute(
            """
            INSERT OR IGNORE INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, ?, '[]', 'ACTIVE', 'mobile_config_parse')
            """,
            (engagement_id, f"auto:mobile_config_parse:{engagement_id}"),
        )

    def _supabase_store_entry(self, config: SupabaseConfig) -> dict[str, str | None]:
        try:
            from forge.opsec.crypto import encrypt_string

            key_enc = encrypt_string(config.anon_key)
        except Exception as exc:  # noqa: BLE001
            _LOG.warning(
                "Supabase anon key encryption unavailable for %s: %s", config.project_ref, exc
            )
            key_enc = None
        return {
            "project_ref": config.project_ref,
            "project_url": config.project_url,
            "source_file": config.source_file,
            "repo_name": Path(config.source_file).name,
            "key_redacted": self._redact_secret(config.anon_key),
            "key_enc": key_enc,
        }

    def extract_supabase_apk(self, apk_path: Path) -> list[SupabaseConfig]:
        configs: list[SupabaseConfig] = []
        if not apk_path.exists():
            return configs
        try:
            with zipfile.ZipFile(apk_path) as zf:
                configs.extend(
                    self._extract_supabase_android_bundle_configs_from_zip(
                        zf,
                        apk_path,
                        nested_prefix="",
                        depth=0,
                    )
                )
        except Exception as exc:
            _LOG.error("Android bundle Supabase extraction error (%s): %s", apk_path, exc)
        return self._dedupe_supabase_configs(configs)

    def extract_supabase_ipa(self, ipa_path: Path) -> list[SupabaseConfig]:
        configs: list[SupabaseConfig] = []
        if not ipa_path.exists():
            return configs
        try:
            with zipfile.ZipFile(ipa_path) as zf:
                text_jobs: list[tuple[str, str, str]] = []
                member_entries = self._phase4_ordered_batch(
                    zf.namelist(),
                    self._supabase_ipa_member_entry,
                    default_factory=lambda: None,
                )
                for member_entry in member_entries:
                    if not isinstance(member_entry, dict):
                        continue
                    text = zf.read(str(member_entry["name"])).decode("utf-8", errors="ignore")
                    text_jobs.append((str(ipa_path), str(member_entry["extract_path"]), text))
                configs.extend(self._extract_supabase_member_text_configs(text_jobs))
        except Exception as exc:
            _LOG.error("IPA Supabase extraction error (%s): %s", ipa_path, exc)
        return self._dedupe_supabase_configs(configs)

    def _extract_supabase_android_bundle_configs_from_zip(
        self,
        zf: zipfile.ZipFile,
        apk_path: Path,
        *,
        nested_prefix: str,
        depth: int,
    ) -> list[SupabaseConfig]:
        configs: list[SupabaseConfig] = []
        text_jobs: list[tuple[str, str, str]] = []
        text_member_entries = self._phase4_ordered_batch(
            zf.namelist(),
            lambda name: self._supabase_android_text_member_entry(
                name,
                nested_prefix=nested_prefix,
            ),
            default_factory=lambda: None,
        )
        for member_entry in text_member_entries:
            if not isinstance(member_entry, dict):
                continue
            name = str(member_entry["name"])
            try:
                text = zf.read(name).decode("utf-8", errors="ignore")
            except Exception as exc:  # noqa: BLE001
                _LOG.debug("Android bundle Supabase member read error (%s): %s", name, exc)
                continue
            text_jobs.append((str(apk_path), str(member_entry["extract_path"]), text))
        configs.extend(self._extract_supabase_member_text_configs(text_jobs))
        if depth >= _NESTED_ANDROID_BUNDLE_MAX_DEPTH:
            return configs
        nested_jobs: list[tuple[bytes, Path, str, int]] = []
        nested_member_entries = self._phase4_ordered_batch(
            zf.namelist(),
            lambda name: self._supabase_android_nested_bundle_entry(
                name,
                nested_prefix=nested_prefix,
            ),
            default_factory=lambda: None,
        )
        for member_entry in nested_member_entries:
            if not isinstance(member_entry, dict):
                continue
            name = str(member_entry["name"])
            try:
                data = zf.read(name)
            except Exception as exc:  # noqa: BLE001
                _LOG.debug("Nested Android bundle Supabase read error (%s): %s", name, exc)
                continue
            nested_jobs.append((data, apk_path, str(member_entry["child_prefix"]), depth + 1))
        if not nested_jobs:
            return configs
        nested_config_batches = self._phase4_ordered_batch(
            nested_jobs,
            self._extract_supabase_nested_bundle_job,
            default_factory=list,
        )
        for config_batch in nested_config_batches:
            configs.extend(config_batch)
        return configs

    def _extract_supabase_member_text_configs(
        self,
        text_jobs: list[tuple[str, str, str]],
    ) -> list[SupabaseConfig]:
        config_batches = self._phase4_ordered_batch(
            text_jobs,
            self._extract_supabase_member_text_job,
            default_factory=list,
        )
        configs: list[SupabaseConfig] = []
        for config_batch in config_batches:
            configs.extend(config_batch)
        return configs

    def _extract_supabase_member_text_job(
        self,
        text_job: tuple[str, str, str],
    ) -> list[SupabaseConfig]:
        source_file, extract_path, text = text_job
        return self._extract_supabase_from_text(text, source_file, extract_path)

    def _extract_supabase_nested_bundle_job(
        self,
        nested_job: tuple[bytes, Path, str, int],
    ) -> list[SupabaseConfig]:
        data, apk_path, nested_prefix, depth = nested_job
        return self._extract_supabase_android_bundle_configs_from_bytes(
            data,
            apk_path,
            nested_prefix=nested_prefix,
            depth=depth,
        )

    @staticmethod
    def _supabase_ipa_member_entry(name: str) -> dict[str, str] | None:
        lower_name = str(name or "").lower()
        if not lower_name.endswith((".plist", ".json", ".js", ".ts")):
            return None
        return {
            "name": str(name),
            "extract_path": str(name),
        }

    def _supabase_android_text_member_entry(
        self,
        name: str,
        *,
        nested_prefix: str,
    ) -> dict[str, str] | None:
        lower_name = str(name or "").lower()
        if "supabase" not in lower_name and not lower_name.endswith((".json", ".js", ".ts")):
            return None
        return {
            "name": str(name),
            "extract_path": self._join_extract_prefix(nested_prefix, str(name)),
        }

    def _supabase_android_nested_bundle_entry(
        self,
        name: str,
        *,
        nested_prefix: str,
    ) -> dict[str, str] | None:
        lower_name = str(name or "").lower()
        suffix = Path(lower_name).suffix
        if suffix not in _ANDROID_BUNDLE_SUFFIXES or lower_name.endswith("/"):
            return None
        return {
            "name": str(name),
            "child_prefix": self._join_extract_prefix(nested_prefix, str(name)),
        }

    def _extract_supabase_android_bundle_configs_from_bytes(
        self,
        data: bytes,
        apk_path: Path,
        *,
        nested_prefix: str,
        depth: int,
    ) -> list[SupabaseConfig]:
        if not data:
            return []
        try:
            with zipfile.ZipFile(BytesIO(data)) as nested_zip:
                return self._extract_supabase_android_bundle_configs_from_zip(
                    nested_zip,
                    apk_path,
                    nested_prefix=nested_prefix,
                    depth=depth,
                )
        except zipfile.BadZipFile:
            _LOG.debug("Nested Android bundle Supabase ZIP invalid (%s)", nested_prefix)
        except Exception as exc:  # noqa: BLE001
            _LOG.debug("Nested Android bundle Supabase parse error (%s): %s", nested_prefix, exc)
        return []

    @staticmethod
    def _google_services_json_member_entry(name: str) -> dict[str, str] | None:
        member_name = str(name or "")
        if not member_name.endswith("google-services.json"):
            return None
        return {"name": member_name}

    @staticmethod
    def _strings_xml_member_entry(name: str) -> dict[str, str] | None:
        member_name = str(name or "")
        if not member_name.endswith("strings.xml"):
            return None
        return {"name": member_name}

    def _firebase_android_nested_bundle_entry(
        self,
        name: str,
        *,
        nested_prefix: str,
    ) -> dict[str, str] | None:
        lower_name = str(name or "").lower()
        suffix = Path(lower_name).suffix
        if suffix not in _ANDROID_BUNDLE_SUFFIXES or lower_name.endswith("/"):
            return None
        return {
            "name": str(name),
            "child_prefix": self._join_extract_prefix(nested_prefix, str(name)),
        }

    @staticmethod
    def _googleservice_plist_member_entry(name: str) -> dict[str, str] | None:
        member_name = str(name or "")
        if not member_name.endswith("GoogleService-Info.plist"):
            return None
        return {"name": member_name}

    @staticmethod
    def _plist_fallback_member_entry(name: str) -> dict[str, str] | None:
        member_name = str(name or "")
        if not member_name.endswith(".plist") or "GoogleService" in member_name:
            return None
        return {"name": member_name}

    # ── APK internal helpers ───────────────────────────────────────────────────

    def _parse_google_services_json(
        self, zf: zipfile.ZipFile, apk_path: Path
    ) -> list[FirebaseProject]:
        projects: list[FirebaseProject] = []
        parse_jobs: list[tuple[Path, str, str]] = []
        candidate_entries = self._phase4_ordered_batch(
            zf.namelist(),
            self._google_services_json_member_entry,
            default_factory=lambda: None,
        )
        for candidate_entry in candidate_entries:
            if not isinstance(candidate_entry, dict):
                continue
            path_in_zip = str(candidate_entry["name"])
            try:
                text = zf.read(path_in_zip).decode("utf-8", errors="replace")
            except Exception as exc:  # noqa: BLE001
                _LOG.debug("google-services.json read error (%s): %s", path_in_zip, exc)
                continue
            parse_jobs.append((apk_path, path_in_zip, text))
        parsed_projects = self._phase4_ordered_batch(
            parse_jobs,
            self._google_services_json_parse_job,
            default_factory=lambda: None,
        )
        projects.extend(
            project for project in parsed_projects if isinstance(project, FirebaseProject)
        )
        return projects

    def _google_services_json_parse_job(
        self,
        parse_job: tuple[Path, str, str],
    ) -> FirebaseProject | None:
        apk_path, path_in_zip, text = parse_job
        try:
            data = json.loads(text)
            project_info = data.get("project_info", {})
            pid = project_info.get("project_id") if isinstance(project_info, dict) else None
            if not pid:
                return None
            rtdb = project_info.get("firebase_url") if isinstance(project_info, dict) else None
            raw_key: Optional[str] = None
            for client in data.get("client", []):
                if not isinstance(client, dict):
                    continue
                for ak in client.get("api_key", []):
                    if not isinstance(ak, dict):
                        continue
                    raw_key = ak.get("current_key")
                    if raw_key:
                        break
                if raw_key:
                    break
            _LOG.info("APK: found project_id=%s in %s", pid, path_in_zip)
            return FirebaseProject(
                project_id=pid,
                api_key_enc=self._encrypt(raw_key),
                rtdb_url=rtdb,
                bundle_id=None,
                source_file=str(apk_path),
                extract_path=path_in_zip,
                storage_bucket=self._normalize_storage_bucket(
                    project_info.get("storage_bucket") if isinstance(project_info, dict) else None
                ),
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            _LOG.debug("google-services.json parse error (%s): %s", path_in_zip, exc)
        return None

    def _scan_strings_xml(self, zf: zipfile.ZipFile, apk_path: Path) -> list[FirebaseProject]:
        projects: list[FirebaseProject] = []
        seen_ids: set[str] = set()
        text_jobs: list[tuple[str, str, str]] = []
        xml_entries = self._phase4_ordered_batch(
            zf.namelist(),
            self._strings_xml_member_entry,
            default_factory=lambda: None,
        )
        for xml_entry in xml_entries:
            if not isinstance(xml_entry, dict):
                continue
            xml_path = str(xml_entry["name"])
            try:
                content = zf.read(xml_path).decode("utf-8", errors="ignore")
            except Exception as exc:
                _LOG.debug("strings.xml read error (%s): %s", xml_path, exc)
                continue
            text_jobs.append((str(apk_path), xml_path, content))
        project_batches = self._phase4_ordered_batch(
            text_jobs,
            self._strings_xml_project_candidates_job,
            default_factory=list,
        )
        for project_batch in project_batches:
            for project in project_batch:
                if project.project_id in seen_ids:
                    continue
                seen_ids.add(project.project_id)
                projects.append(project)
        return projects

    @staticmethod
    def _strings_xml_project_candidates_job(
        text_job: tuple[str, str, str],
    ) -> list[FirebaseProject]:
        source_file, xml_path, content = text_job
        projects: list[FirebaseProject] = []
        try:
            for m in _RTDB_URL_RE.finditer(content):
                project_id = m.group(1).replace("-default-rtdb", "")
                projects.append(
                    FirebaseProject(
                        project_id=project_id,
                        api_key_enc=None,
                        rtdb_url=m.group(0),
                        bundle_id=None,
                        source_file=source_file,
                        extract_path=xml_path,
                    )
                )
                _LOG.info("APK fallback: RTDB URL found → project_id=%s", project_id)
        except Exception as exc:  # noqa: BLE001
            _LOG.debug("strings.xml scan error (%s): %s", xml_path, exc)
        return projects

    def _extract_android_bundle_projects_from_zip(
        self,
        zf: zipfile.ZipFile,
        apk_path: Path,
        *,
        nested_prefix: str,
        depth: int,
    ) -> list[FirebaseProject]:
        projects = self._parse_google_services_json(zf, apk_path)
        if not projects:
            projects.extend(self._scan_strings_xml(zf, apk_path))
        rebased_projects = self._rebase_firebase_projects(projects, nested_prefix, apk_path)
        if depth >= _NESTED_ANDROID_BUNDLE_MAX_DEPTH:
            return rebased_projects
        nested_jobs: list[tuple[bytes, Path, str, int]] = []
        nested_member_entries = self._phase4_ordered_batch(
            zf.namelist(),
            lambda name: self._firebase_android_nested_bundle_entry(
                name,
                nested_prefix=nested_prefix,
            ),
            default_factory=lambda: None,
        )
        for member_entry in nested_member_entries:
            if not isinstance(member_entry, dict):
                continue
            name = str(member_entry["name"])
            try:
                data = zf.read(name)
            except Exception as exc:  # noqa: BLE001
                _LOG.debug("Nested Android bundle read error (%s): %s", name, exc)
                continue
            nested_jobs.append((data, apk_path, str(member_entry["child_prefix"]), depth + 1))
        if not nested_jobs:
            return rebased_projects
        nested_project_batches = self._phase4_ordered_batch(
            nested_jobs,
            self._extract_firebase_nested_bundle_job,
            default_factory=list,
        )
        for project_batch in nested_project_batches:
            rebased_projects.extend(project_batch)
        return rebased_projects

    def _extract_firebase_nested_bundle_job(
        self,
        nested_job: tuple[bytes, Path, str, int],
    ) -> list[FirebaseProject]:
        data, apk_path, nested_prefix, depth = nested_job
        return self._extract_android_bundle_projects_from_bytes(
            data,
            apk_path,
            nested_prefix=nested_prefix,
            depth=depth,
        )

    def _extract_android_bundle_projects_from_bytes(
        self,
        data: bytes,
        apk_path: Path,
        *,
        nested_prefix: str,
        depth: int,
    ) -> list[FirebaseProject]:
        if not data:
            return []
        try:
            with zipfile.ZipFile(BytesIO(data)) as nested_zip:
                return self._extract_android_bundle_projects_from_zip(
                    nested_zip,
                    apk_path,
                    nested_prefix=nested_prefix,
                    depth=depth,
                )
        except zipfile.BadZipFile:
            _LOG.debug("Nested Android bundle is not a valid ZIP (%s)", nested_prefix)
        except Exception as exc:  # noqa: BLE001
            _LOG.debug("Nested Android bundle parse error (%s): %s", nested_prefix, exc)
        return []

    # ── IPA internal helpers ───────────────────────────────────────────────────

    def _parse_googleservice_plist(
        self, zf: zipfile.ZipFile, ipa_path: Path
    ) -> list[FirebaseProject]:
        projects: list[FirebaseProject] = []
        parse_jobs: list[tuple[Path, str, bytes]] = []
        candidate_entries = self._phase4_ordered_batch(
            zf.namelist(),
            self._googleservice_plist_member_entry,
            default_factory=lambda: None,
        )
        for candidate_entry in candidate_entries:
            if not isinstance(candidate_entry, dict):
                continue
            path_in_zip = str(candidate_entry["name"])
            try:
                parse_jobs.append((ipa_path, path_in_zip, zf.read(path_in_zip)))
            except Exception as exc:
                _LOG.debug("GoogleService-Info.plist read error (%s): %s", path_in_zip, exc)
        parsed_projects = self._phase4_ordered_batch(
            parse_jobs,
            self._googleservice_plist_parse_job,
            default_factory=lambda: None,
        )
        projects.extend(
            project for project in parsed_projects if isinstance(project, FirebaseProject)
        )
        return projects

    def _googleservice_plist_parse_job(
        self,
        parse_job: tuple[Path, str, bytes],
    ) -> FirebaseProject | None:
        ipa_path, path_in_zip, data_bytes = parse_job
        try:
            data = plistlib.loads(data_bytes)
            pid = data.get("PROJECT_ID")
            if not pid:
                return None
            raw_key = data.get("API_KEY")
            _LOG.info("IPA: found project_id=%s in %s", pid, path_in_zip)
            return FirebaseProject(
                project_id=pid,
                api_key_enc=self._encrypt(raw_key),
                rtdb_url=data.get("DATABASE_URL"),
                bundle_id=data.get("BUNDLE_ID"),
                source_file=str(ipa_path),
                extract_path=path_in_zip,
                storage_bucket=self._normalize_storage_bucket(data.get("STORAGE_BUCKET")),
            )
        except Exception as exc:  # noqa: BLE001
            _LOG.debug("GoogleService-Info.plist parse error (%s): %s", path_in_zip, exc)
        return None

    def _scan_plist_files(self, zf: zipfile.ZipFile, ipa_path: Path) -> list[FirebaseProject]:
        projects: list[FirebaseProject] = []
        seen_ids: set[str] = set()
        text_jobs: list[tuple[str, str, str]] = []
        plist_entries = self._phase4_ordered_batch(
            zf.namelist(),
            self._plist_fallback_member_entry,
            default_factory=lambda: None,
        )
        for plist_entry in plist_entries:
            if not isinstance(plist_entry, dict):
                continue
            plist_path = str(plist_entry["name"])
            try:
                content = zf.read(plist_path).decode("utf-8", errors="ignore")
                text_jobs.append((str(ipa_path), plist_path, content))
            except Exception as exc:
                _LOG.debug("plist read error (%s): %s", plist_path, exc)
        project_batches = self._phase4_ordered_batch(
            text_jobs,
            self._plist_fallback_project_candidates_job,
            default_factory=list,
        )
        for project_batch in project_batches:
            for project in project_batch:
                if project.project_id in seen_ids:
                    continue
                seen_ids.add(project.project_id)
                projects.append(project)
        return projects

    @staticmethod
    def _plist_fallback_project_candidates_job(
        text_job: tuple[str, str, str],
    ) -> list[FirebaseProject]:
        source_file, plist_path, content = text_job
        projects: list[FirebaseProject] = []
        try:
            for m in _RTDB_URL_RE.finditer(content):
                project_id = m.group(1).replace("-default-rtdb", "")
                projects.append(
                    FirebaseProject(
                        project_id=project_id,
                        api_key_enc=None,
                        rtdb_url=m.group(0),
                        bundle_id=None,
                        source_file=source_file,
                        extract_path=plist_path,
                    )
                )
                _LOG.info("IPA fallback: RTDB URL found -> project_id=%s", project_id)
        except Exception as exc:  # noqa: BLE001
            _LOG.debug("plist scan error (%s): %s", plist_path, exc)
        return projects

    # ── Utility ────────────────────────────────────────────────────────────────

    def _encrypt(self, raw_key: Optional[str]) -> Optional[str]:
        if not raw_key:
            return None
        if not self._age_pubkey:
            _LOG.warning(
                "No age_pubkey provided; API key stored as PLACEHOLDER — "
                "re-run with age_pubkey to encrypt properly."
            )
            return "__UNENCRYPTED_PLACEHOLDER__"
        try:
            from forge.opsec.crypto import encrypt_string

            return encrypt_string(raw_key, self._age_pubkey)
        except ImportError:
            _LOG.warning("forge.opsec.crypto unavailable; key not encrypted")
            return None

    @staticmethod
    def _register_cleanup(path: Path) -> None:
        try:
            from forge.shared.cleanup import register_cleanup_file

            register_cleanup_file(path)
        except ImportError:
            pass

    @staticmethod
    def _normalize_storage_bucket(value: object) -> Optional[str]:
        bucket = str(value or "").strip().lower()
        if not bucket:
            return None
        if not re.fullmatch(r"[a-z0-9._\-]{3,222}", bucket):
            return None
        return bucket

    @staticmethod
    def _join_extract_prefix(prefix: str, child: str) -> str:
        normalized_child = str(child or "").strip()
        if not prefix:
            return normalized_child
        if not normalized_child:
            return prefix
        return f"{prefix}!{normalized_child}"

    @staticmethod
    def _firebase_rebase_project_entry(
        project: FirebaseProject,
        *,
        nested_prefix: str,
        apk_path: Path,
    ) -> FirebaseProject:
        return FirebaseProject(
            project_id=project.project_id,
            api_key_enc=project.api_key_enc,
            rtdb_url=project.rtdb_url,
            bundle_id=project.bundle_id,
            source_file=str(apk_path),
            extract_path=FirebaseExtractor._join_extract_prefix(
                nested_prefix, project.extract_path
            ),
            storage_bucket=project.storage_bucket,
        )

    @staticmethod
    def _rebase_firebase_projects(
        projects: list[FirebaseProject],
        nested_prefix: str,
        apk_path: Path,
    ) -> list[FirebaseProject]:
        if not nested_prefix:
            return projects
        rebased_projects = FirebaseExtractor._phase4_ordered_batch(
            projects,
            lambda project: FirebaseExtractor._firebase_rebase_project_entry(
                project,
                nested_prefix=nested_prefix,
                apk_path=apk_path,
            ),
            default_factory=lambda: None,
        )
        return [project for project in rebased_projects if isinstance(project, FirebaseProject)]

    @staticmethod
    def _redact_secret(value: str, *, keep: int = 4) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        if len(text) <= keep * 2:
            return "*" * len(text)
        return f"{text[:keep]}...{text[-keep:]}"

    @staticmethod
    def _supabase_project_ref_from_anon_key(value: str) -> str:
        token = str(value or "").strip()
        if not token:
            return ""
        parts = token.split(".")
        if len(parts) < 2:
            return ""
        payload = parts[1].strip()
        if not payload:
            return ""
        padded = payload + ("=" * (-len(payload) % 4))
        try:
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
            data = json.loads(decoded.decode("utf-8", errors="ignore"))
        except Exception:  # noqa: BLE001
            return ""
        project_ref = str(data.get("ref") or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9\-]{3,}", project_ref):
            return ""
        return project_ref

    @staticmethod
    def _extract_supabase_from_text(
        text: str, source_file: str, extract_path: str
    ) -> list[SupabaseConfig]:
        urls = [str(url_ref or "").strip().lower() for url_ref in _SUPABASE_URL_RE.findall(text)]
        keys = _SUPABASE_KEY_RE.findall(text)
        if not keys:
            return []
        unique_url_refs = [value for value in dict.fromkeys(urls) if value]
        if len(keys) == 1:
            return FirebaseExtractor._supabase_config_candidates_for_key(
                keys[0],
                unique_url_refs,
                source_file,
                extract_path,
            )
        ordered_results = FirebaseExtractor._phase4_ordered_batch(
            keys,
            lambda key: FirebaseExtractor._supabase_config_candidates_for_key(
                key,
                unique_url_refs,
                source_file,
                extract_path,
            ),
            default_factory=list,
        )
        configs: list[SupabaseConfig] = []
        for result in ordered_results:
            if not result:
                continue
            configs.extend(result)
        return configs

    @staticmethod
    def _supabase_config_candidates_for_key(
        key: str,
        unique_url_refs: list[str],
        source_file: str,
        extract_path: str,
    ) -> list[SupabaseConfig]:
        key_ref = FirebaseExtractor._supabase_project_ref_from_anon_key(key)
        candidate_refs: list[str] = []
        if key_ref:
            candidate_refs.append(key_ref)
        elif unique_url_refs:
            candidate_refs.extend(unique_url_refs)
        return [
            SupabaseConfig(
                project_ref=project_ref,
                project_url=f"https://{project_ref}.supabase.co",
                anon_key=key,
                source_file=source_file,
                extract_path=extract_path,
            )
            for project_ref in candidate_refs
        ]

    @staticmethod
    def _dedupe_supabase_configs(configs: list[SupabaseConfig]) -> list[SupabaseConfig]:
        deduped: list[SupabaseConfig] = []
        seen: set[tuple[str, str]] = set()
        if len(configs) <= 1:
            return list(configs)
        ordered_keys = FirebaseExtractor._phase4_ordered_batch(
            configs,
            FirebaseExtractor._supabase_dedupe_key,
            default_factory=lambda: None,
        )
        for cfg, key in zip(configs, ordered_keys):
            if key is None:
                continue
            if key in seen:
                continue
            seen.add(key)
            deduped.append(cfg)
        return deduped

    @staticmethod
    def _dedupe_firebase_projects(projects: list[FirebaseProject]) -> list[FirebaseProject]:
        deduped: list[FirebaseProject] = []
        seen: set[tuple[str, Optional[str], Optional[str]]] = set()
        if len(projects) <= 1:
            return list(projects)
        ordered_keys = FirebaseExtractor._phase4_ordered_batch(
            projects,
            FirebaseExtractor._firebase_dedupe_key,
            default_factory=lambda: None,
        )
        for project, key in zip(projects, ordered_keys):
            if key is None:
                continue
            if key in seen:
                continue
            seen.add(key)
            deduped.append(project)
        return deduped

    @staticmethod
    def _supabase_dedupe_key(cfg: SupabaseConfig) -> tuple[str, str] | None:
        return (cfg.project_ref, cfg.anon_key)

    @staticmethod
    def _firebase_dedupe_key(
        project: FirebaseProject,
    ) -> tuple[str, Optional[str], Optional[str]] | None:
        return (project.project_id, project.rtdb_url, project.source_file)

    @staticmethod
    def _ensure_schema(con: sqlite3.Connection) -> None:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS cloud_assets (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                asset_type    TEXT NOT NULL,
                identifier    TEXT NOT NULL,
                provider_identifier TEXT,
                source        TEXT NOT NULL,
                discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, asset_type, identifier)
            );
        """)
        try:
            con.execute("ALTER TABLE cloud_assets ADD COLUMN provider_identifier TEXT")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise
        con.commit()
