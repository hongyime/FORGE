"""Google account enrichment via GHunt (Module 2-G).

GHunt (https://github.com/mxrch/GHunt) is a passive OSINT tool that
enriches a Gmail address into a Google-account fingerprint by hitting
Google's own public endpoints using a signed-in session cookie:

  - Google ID (gaia_id)
  - Display name + profile picture
  - Custom URL / @handle
  - Public Maps reviews (locations visited)
  - Public Play Games profile (games, achievements)
  - Public Calendar events
  - Linked YouTube channel

Because GHunt piggybacks on a real Google session it requires a one-time
cookie setup (`ghunt login`), stored in a local `creds.m` file. If no
creds file exists we short-circuit and surface the reason in the return
dict — the kill-chain caller decides whether to skip.

Non-fatal on every failure (missing binary, missing creds, timeout,
subprocess crash, non-JSON output). Empty/error dict on any error.
"""

from __future__ import annotations

import json
import os
import shlex
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

from forge.utils.intel.tool_paths import find_tool_binary
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect


def _ghunt_creds_path() -> Path:
    """Return the first existing creds.m path, or the preferred candidate.

    GHunt on Windows writes to ``%APPDATA%/ghunt/creds.m``. On POSIX (and
    as a legacy fallback on Windows too) it writes to
    ``~/.malfrats/ghunt/creds.m``. We check both and return the first that
    exists; if neither exists we return the platform-preferred path so
    callers can display a helpful "run `ghunt login`" message.
    """
    candidates: list[Path] = []
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "ghunt" / "creds.m")
        candidates.append(Path.home() / ".malfrats" / "ghunt" / "creds.m")
    else:
        candidates.append(Path.home() / ".malfrats" / "ghunt" / "creds.m")
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "ghunt" / "creds.m")
    for candidate in candidates:
        try:
            if candidate.exists():
                return candidate
        except OSError:
            continue
    return candidates[0]


def _ghunt_creds_available() -> bool:
    """Quick check whether a usable GHunt cookie file is present."""
    try:
        return _ghunt_creds_path().exists()
    except OSError:
        return False


def _ghunt_binary() -> Optional[str]:
    """Locate the ghunt executable via PATH, OSINT tool venvs, then active venv."""
    configured = os.environ.get("FORGE_GHUNT_BINARY", "").strip()
    if configured:
        return configured
    return find_tool_binary("ghunt")


def _ghunt_command() -> list[str]:
    """Return the command prefix used to invoke GHunt.

    ``ghunt`` has a tighter dependency graph than FORGE's core runtime. Operators
    can point this at a tool-specific virtualenv, for example:
    ``FORGE_GHUNT_COMMAND="C:\\tools\\ghunt\\.venv\\Scripts\\python.exe -m ghunt"``.
    """
    configured_command = os.environ.get("FORGE_GHUNT_COMMAND", "").strip()
    if configured_command:
        return [
            part.strip("\"'")
            for part in shlex.split(configured_command, posix=os.name != "nt")
            if part.strip("\"'")
        ]
    binary = _ghunt_binary()
    return [binary] if binary else []


def _safe(obj: Any, key: str, default: Any = None) -> Any:
    """Dict-safe get that tolerates non-dict inputs."""
    return obj.get(key, default) if isinstance(obj, dict) else default


def lookup_google_account(
    email: str,
    engagement_id: int,
    db_path: Path,
    timeout: float = 30.0,
    proxy: Optional[str] = None,
) -> dict[str, Any]:
    """Enrich a Gmail address via GHunt.

    Returns dict:
      {
        "email":     <normalised>,
        "available": bool,          # False => tool/creds missing
        "found":     bool,          # True  => JSON parsed successfully
        "reason":    <str>,         # populated when available=False
        "error":     <str>,         # populated when subprocess/parse fails
        "profile":   {
            "gaia_id":       ...,
            "name":          ...,
            "profile_pic":   ...,
            "custom_url":    ...,
            "email":         ...,
            "youtube":       {...} or None,
            "maps_reviews":  [...],
            "play_games":    {...} or None,
            "calendar":      {...} or None,
        },
        "raw": <full ghunt JSON dict>,
      }

    Never raises. Every failure path returns a populated dict — the
    kill-chain treats an empty/error dict as "skip and move on".

    `engagement_id` and `db_path` are accepted for signature symmetry with
    the other 2-* modules (they aren't touched here; persistence lives in
    :func:`persist_google_findings`).
    """
    _ = engagement_id, db_path  # signature symmetry; unused in lookup

    result: dict[str, Any] = {
        "email": email.strip().lower(),
        "available": False,
        "found": False,
        "profile": {},
    }

    command = _ghunt_command()
    if not command:
        result["reason"] = "ghunt binary not found"
        return result

    result["available"] = True

    if not _ghunt_creds_available():
        result["error"] = "no cookie configured"
        return result

    # ghunt writes JSON to whatever path we hand it via --json. Use a
    # tempfile so we don't pollute the project dir; delete=False so the
    # subprocess can write to it on Windows (where a still-open handle
    # blocks re-open from another process).
    tmp = tempfile.NamedTemporaryFile(
        prefix="ghunt-",
        suffix=".json",
        delete=False,
        mode="w",
    )
    tmp.close()
    tmp_path = Path(tmp.name)

    try:
        process_env = None
        proxy_value = str(proxy or "").strip()
        if proxy_value:
            process_env = os.environ.copy()
            process_env["HTTP_PROXY"] = proxy_value
            process_env["HTTPS_PROXY"] = proxy_value
            process_env["ALL_PROXY"] = proxy_value
        try:
            proc = subprocess.run(
                [*command, "email", "--json", str(tmp_path), email.strip()],
                capture_output=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                env=process_env,
                check=False,
            )
            # manually decode outputs
            proc_stdout = proc.stdout.decode("utf-8", "replace") if proc.stdout else ""
            proc_stderr = proc.stderr.decode("utf-8", "replace") if proc.stderr else ""
        except subprocess.TimeoutExpired:
            result["error"] = f"timeout after {timeout}s"
            return result
        except (OSError, FileNotFoundError) as exc:
            result["error"] = f"subprocess: {type(exc).__name__}: {exc}"
            return result
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"subprocess: {type(exc).__name__}: {exc}"
            return result

        # ghunt may exit non-zero on "no account found" but still emit
        # useful JSON; we only fail hard if the file was never written.
        if not tmp_path.exists() or tmp_path.stat().st_size == 0:
            tail = ""
            if proc_stderr:
                tail = proc_stderr.strip().splitlines()[-1] if proc_stderr.strip() else ""
            if not tail and proc_stdout:
                tail = proc_stdout.strip().splitlines()[-1] if proc_stdout.strip() else ""
            result["error"] = (
                f"ghunt failed (exit {proc.returncode}): {tail[:200]}"
                if tail
                else f"ghunt produced no output (exit {proc.returncode})"
            )
            return result

        try:
            raw_text = tmp_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result["error"] = f"read json: {exc}"
            return result

        if not raw_text.strip():
            result["error"] = "empty ghunt output"
            return result

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            result["error"] = f"non-JSON ghunt output: {exc}"
            return result
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass

    if not isinstance(data, dict) or not data:
        return result

    result["raw"] = data
    result["found"] = True

    # GHunt v2.3.4 real schema (verified 2026-07-08):
    #   PROFILE_CONTAINER.profile.personId               -> gaia_id
    #   PROFILE_CONTAINER.profile.emails.PROFILE.value   -> email
    #   PROFILE_CONTAINER.profile.sourceIds.PROFILE.lastUpdated -> last_edit
    #   PROFILE_CONTAINER.profile.inAppReachability.PROFILE.apps -> apps list
    #   PROFILE_CONTAINER.play_games                     -> play games profile
    #   PROFILE_CONTAINER.maps                           -> maps container
    #   PROFILE_CONTAINER.calendar                       -> calendar container
    profile_container = _safe(data, "PROFILE_CONTAINER") or {}
    profile_obj = _safe(profile_container, "profile", {}) or {}
    play_games = _safe(profile_container, "play_games")
    maps_container = _safe(profile_container, "maps") or {}
    calendar = _safe(profile_container, "calendar")

    gaia_id = _safe(profile_obj, "personId", "") or ""

    # Real name extraction (profile.names.PROFILE.fullname when present)
    names_data = _safe(profile_obj, "names", {}) or {}
    name = ""
    if isinstance(names_data, dict):
        prof_names = _safe(names_data, "PROFILE") or _safe(names_data, "profile") or {}
        if isinstance(prof_names, dict):
            name = _safe(prof_names, "fullname", "") or _safe(prof_names, "displayName", "") or ""

    # Profile picture URL
    profile_pics = _safe(profile_obj, "profilePhotos", {}) or {}
    pic = ""
    if isinstance(profile_pics, dict):
        prof_pic = _safe(profile_pics, "PROFILE") or {}
        if isinstance(prof_pic, dict):
            pic = _safe(prof_pic, "url", "") or ""

    # Custom URL (rare on modern Gmail accounts)
    custom_url = _safe(profile_obj, "customUrl", "") or ""

    # Activated Google services (Maps, Meet, Drive, YouTube, etc.)
    apps: list[str] = []
    reach = _safe(profile_obj, "inAppReachability", {}) or {}
    if isinstance(reach, dict):
        for container_reach in reach.values():
            if isinstance(container_reach, dict):
                for a in _safe(container_reach, "apps", []) or []:
                    if isinstance(a, str) and a not in apps:
                        apps.append(a)

    # Last profile edit
    last_edit = ""
    source_ids = _safe(profile_obj, "sourceIds", {}) or {}
    if isinstance(source_ids, dict):
        prof_src = _safe(source_ids, "PROFILE") or {}
        if isinstance(prof_src, dict):
            last_edit = _safe(prof_src, "lastUpdated", "") or ""

    # Maps reviews (present when user has any public review)
    maps_reviews = []
    if isinstance(maps_container, dict):
        maps_reviews = _safe(maps_container, "reviews", []) or []

    # YouTube channel handle (if account has one linked)
    youtube = None
    services = _safe(profile_obj, "services", {})
    if isinstance(services, dict):
        youtube = _safe(services, "youtube")

    result["profile"] = {
        "gaia_id": str(gaia_id) if gaia_id else "",
        "name": name or "",
        "display_name": name or "",
        "profile_pic": pic or "",
        "custom_url": custom_url or "",
        "youtube": youtube,
        "maps_reviews": maps_reviews if isinstance(maps_reviews, list) else [],
        "play_games": play_games,
        "calendar": calendar,
        "apps": apps,
        "last_edit": last_edit,
        "raw": data,
    }
    return result


def persist_google_findings(
    email: str,
    engagement_id: int,
    db_path: Path,
    profile: dict[str, Any],
) -> int:
    """Persist GHunt findings into ``social_profiles`` + ``audit_log``.

    Writes:
      - One ``source='ghunt'`` summary row keyed to the email.
      - One ``source='ghunt:youtube:<handle>'`` row per linked YouTube
        channel so the E5 fan-out feeds the handle into Sherlock.
      - One ``source='ghunt:playgames'`` row for a Play Games handle.
      - One ``source='ghunt:maps:<id>'`` row per public Maps review
        (capped at 50 rows to bound blast radius).
      - One ``audit_log`` row (phase='phase2', module='google_account').

    Returns the count of new ``social_profiles`` rows written. An empty
    dict or a lookup with ``found=False`` is skipped silently.
    """
    if not profile or not profile.get("found"):
        return 0
    inner = profile.get("profile") or {}
    if not inner:
        return 0

    written = 0
    try:
        con = direct_connect(str(db_path))
    except sqlite3.OperationalError:
        return 0
    try:
        try:
            con.execute("""
                CREATE TABLE IF NOT EXISTS social_profiles (
                    id              INTEGER PRIMARY KEY,
                    engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
                    email           TEXT NOT NULL,
                    source          TEXT NOT NULL DEFAULT 'epieos',
                    profile_data    TEXT,
                    queried_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(engagement_id, email, source)
                )
            """)
        except sqlite3.OperationalError:
            pass

        email_l = email.strip().lower()

        # -- Summary row --
        summary = json.dumps(
            {
                "source": "ghunt",
                "gaia_id": inner.get("gaia_id", ""),
                "name": inner.get("name", ""),
                "custom_url": inner.get("custom_url", ""),
                "profile_pic": inner.get("profile_pic", ""),
                "has_youtube": bool(inner.get("youtube")),
                "has_playgames": bool(inner.get("play_games")),
                "has_calendar": bool(inner.get("calendar")),
                "maps_review_count": len(inner.get("maps_reviews", []) or []),
                "handle": inner.get("custom_url", "") or inner.get("name", ""),
            }
        )
        try:
            con.execute(
                "INSERT INTO social_profiles "
                "(engagement_id, email, source, profile_data) "
                "VALUES (?, ?, ?, ?)",
                (engagement_id, email_l, "ghunt", summary),
            )
            written += 1
        except (sqlite3.OperationalError, sqlite3.IntegrityError):
            pass

        # -- Linked YouTube channel (feeds Sherlock fan-out) --
        yt = inner.get("youtube") or {}
        if isinstance(yt, dict) and yt:
            yt_handle = (
                yt.get("custom_url")
                or yt.get("channel_id")
                or yt.get("channel_name")
                or yt.get("name")
                or ""
            )
            if yt_handle:
                yt_handle_s = str(yt_handle).lstrip("@")
                payload = json.dumps(
                    {
                        "source": "ghunt",
                        "handle": yt_handle_s,
                        "platform": "youtube",
                        "url": yt.get("url", ""),
                        "email": email_l,
                    }
                )
                try:
                    con.execute(
                        "INSERT INTO social_profiles "
                        "(engagement_id, email, source, profile_data) "
                        "VALUES (?, ?, ?, ?)",
                        (engagement_id, email_l, f"ghunt:youtube:{yt_handle_s[:32]}", payload),
                    )
                    written += 1
                except (sqlite3.OperationalError, sqlite3.IntegrityError):
                    pass

        # -- Play Games profile --
        pg = inner.get("play_games") or {}
        if isinstance(pg, dict) and pg:
            pg_handle = (
                pg.get("player_name")
                or pg.get("nickname")
                or pg.get("display_name")
                or pg.get("name")
                or ""
            )
            payload = json.dumps(
                {
                    "source": "ghunt",
                    "handle": str(pg_handle),
                    "platform": "play_games",
                    "avatar": pg.get("avatar_url", "") or pg.get("avatar", ""),
                    "email": email_l,
                }
            )
            try:
                con.execute(
                    "INSERT INTO social_profiles "
                    "(engagement_id, email, source, profile_data) "
                    "VALUES (?, ?, ?, ?)",
                    (engagement_id, email_l, "ghunt:playgames", payload),
                )
                written += 1
            except (sqlite3.OperationalError, sqlite3.IntegrityError):
                pass

        # -- Public Maps reviews (each location; capped at 50) --
        reviews = inner.get("maps_reviews") or []
        if isinstance(reviews, list):
            for idx, rev in enumerate(reviews[:50]):
                if not isinstance(rev, dict):
                    continue
                loc_obj = rev.get("location")
                if isinstance(loc_obj, dict):
                    loc = loc_obj.get("name", "") or loc_obj.get("address", "")
                else:
                    loc = rev.get("place_name") or rev.get("name") or ""
                rev_id = rev.get("id") or rev.get("review_id") or idx
                payload = json.dumps(
                    {
                        "source": "ghunt",
                        "platform": "maps_review",
                        "location": str(loc),
                        "rating": rev.get("rating"),
                        "comment": (rev.get("comment", "") or "")[:200],
                        "email": email_l,
                    }
                )
                try:
                    con.execute(
                        "INSERT INTO social_profiles "
                        "(engagement_id, email, source, profile_data) "
                        "VALUES (?, ?, ?, ?)",
                        (engagement_id, email_l, f"ghunt:maps:{str(rev_id)[:32]}", payload),
                    )
                    written += 1
                except (sqlite3.OperationalError, sqlite3.IntegrityError):
                    pass

        # -- Audit log entry for verifiability --
        try:
            con.execute(
                "INSERT INTO audit_log "
                "(engagement_id, phase, module, action, target, result, operator) "
                "VALUES (?, 'phase2', 'google_account', 'lookup', ?, ?, ?)",
                (engagement_id, email_l, summary, "kill_chain"),
            )
        except sqlite3.OperationalError:
            pass
        con.commit()
    finally:
        con.close()
    return written
