"""
forge/config.py — FORGE runtime configuration.

All configuration is sourced from environment variables only. No .env file
is auto-loaded to prevent accidental credential leakage from disk. Operators
must export variables explicitly in their shell session.

OPSEC contract (PRD v7.2 §12.1):
  - HISTCONTROL=ignorespace must be set before exporting secrets.
  - FORGE_ENGAGEMENT_KEY must never be written to disk unencrypted.
  - FORGE_OFFLINE_STRICT=1 disables all outbound sockets at process level
    (enforced in cli.py callback); ForgeConfig exposes it for introspection.

Environment variables:

  FORGE_DATA_DIR         Base directory for all generated data (DBs, payloads).
                         Default: ~/.forge/data
  FORGE_LOG_LEVEL        Logging verbosity: DEBUG | INFO | WARNING | ERROR.
                         Default: INFO
  FORGE_OFFLINE_STRICT   Set to "1" to hard-disable outbound network calls.
                         Default: 0 (disabled)
  FORGE_SAFE_MODE        Set to "1" to disable offensive modules (Phase 3
                         payload generation, Phase 5 post-exploitation).
                         Core phases (0, 1, 2 OSINT, 4 correlation, 6 report)
                         remain fully functional.  This prevents AV engines
                         from flagging impacket, credential collectors, and
                         obfuscation code that ship with the full install.
                         Default: 0 (offensive modules enabled)
  FORGE_ENGAGEMENT_KEY   Age private key material for encrypting engagement DBs.
                         Must be set before any DB write. Never logged.
  FORGE_OPERATOR         Operator handle written to audit_log. Defaults to
                         the OS username if unset.
  FORGE_KB_PATH          Explicit path to lolbas.db. Blank value is ignored.
                         Overrides default under
                         FORGE_DATA_DIR.
  FORGE_NVD_PATH         Explicit path to nvd_cache.db. Blank value is ignored.
  FORGE_EXPLOITDB_PATH   Explicit path to ref_cache.db (obfuscated exploit cache).
                         Blank value is ignored.
  FORGE_EXPLOITDB_CSV    Explicit path to Exploit-DB files_exploits.csv.
                         Blank value is ignored.
  FORGE_EXPLOITDB_CSV    Explicit path to Exploit-DB files_exploits.csv.
  FORGE_CURL_IMPERSONATE Browser profile for curl_cffi TLS impersonation.
                         Default: chrome120
  FORGE_PROXY            HTTP/HTTPS proxy for all outbound requests (Phase 0 only).
  FORGE_AWS_PROFILE      Default AWS profile for forge cloud aws command.
  FORGE_AWS_REGIONS      Default CSV AWS regions for forge cloud aws command.
  FORGE_AWS_SERVICES     Default CSV AWS services for forge cloud aws command.
  FORGE_AZURE_SUBSCRIPTION_ID
                         Default Azure subscription ID for forge cloud azure command.
  FORGE_AZURE_TENANT_ID  Default Azure tenant ID for forge cloud azure command.
  FORGE_AZURE_CLIENT_ID  Default Azure client ID for forge cloud azure command.
  FORGE_AZURE_SERVICES   Default CSV Azure services for forge cloud azure command.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_DATA_DIR: Path = Path.home() / ".forge" / "data"
_VALID_LOG_LEVELS: frozenset[str] = frozenset({"DEBUG", "INFO", "WARNING", "ERROR"})
_VALID_CURL_PROFILES: frozenset[str] = frozenset(
    {
        "chrome99",
        "chrome100",
        "chrome101",
        "chrome104",
        "chrome107",
        "chrome110",
        "chrome116",
        "chrome120",
        "firefox91esr",
        "firefox98",
        "firefox100",
        "firefox102",
        "safari15_3",
        "safari15_5",
    }
)

# Canonical → obfuscated directory mapping (PRD v7.2 §12.6).
# Used by scaffold generator and check_filenames CI script.
OBFUSCATED_DIR_MAP: dict[str, str] = {
    "phase2": "utils/intel",
    "phase5": "utils/post",
}

# Canonical → obfuscated filename mapping (PRD v7.2 §12.6).
OBFUSCATED_FILE_MAP: dict[str, str] = {
    "breach_db.py": "data_connector.py",
    "credential_validator.py": "auth_check.py",
    "dehashed.py": "index_query.py",
    "xposedornot.py": "exposure_check.py",
    "theharvester.py": "contact_enum.py",
    "emailrep.py": "reputation_lookup.py",
    "epieos.py": "social_scraper.py",
    "username_enum.py": "handle_finder.py",
    "reverse_shell.py": "template_engine.py",
    "c2_generator.py": "session_manager.py",
    "exfiltration.py": "transfer_util.py",
    "persistence.py": "schedule_builder.py",
    "lateral_movement.py": "remote_exec.py",
    "scope_gate.py": "boundary_check.py",
    "key_scanner.py": "secret_finder.py",
    "idor_scanner.py": "param_probe.py",
    "firebase_agneyastra.py": "cloud_audit.py",
    "firebase_extract.py": "mobile_config_parse.py",
    "supabase_scanner.py": "api_policy_check.py",
    "exploit_cache.db": "ref_cache.db",
}

# Canonical names that must NEVER appear on disk in obfuscated directories.
BANNED_CANONICAL_NAMES: frozenset[str] = frozenset(OBFUSCATED_FILE_MAP.keys()) | frozenset(
    {
        "phase2",
        "phase5",
        "breach_query_log",
        "exfiltrated_data",
        "agents",
        "payloads",
    }
)


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ForgeConfig:
    """Immutable runtime configuration snapshot.

    Construct via :meth:`ForgeConfig.load` — never instantiate directly in
    application code to ensure consistent env-var resolution.
    """

    data_dir: Path
    log_level: str
    offline_strict: bool
    safe_mode: bool
    operator: str
    kb_path: Path
    nvd_path: Path
    exploitdb_path: Path
    exploitdb_csv_path: Path | None
    curl_profile: str
    proxy: str | None
    supabase_auto_discovery: bool
    mobile_assets_scan: bool
    repo_key_scavenge: bool
    firebase_web_discovery: bool
    firebase_repo_scavenge: bool
    web_enabled: bool
    web_host: str
    web_port: int
    web_auth: str
    web_secret_key: str
    distributed_enabled: bool
    redis_url: str | None
    max_workers: int
    task_timeout: int
    browser_headless: bool
    browser_timeout: int
    screenshot_enabled: bool
    cdn_detection: bool
    waf_detection: bool
    shodan_key: str | None
    auth_max_attempts: int
    auth_rate_limit: int
    c2_default_channel: str
    c2_fallback_order: list[str]
    c2_failure_threshold_https: int
    c2_failure_threshold_dns: int
    c2_failure_threshold_smb: int
    c2_failure_threshold_icmp: int
    c2_smb_pipe_name: str
    c2_smb_fallback_timeout: int
    c2_icmp_target_ip: str
    c2_icmp_packet_interval: int
    cloud_aws_profile: str | None
    cloud_aws_regions: list[str]
    cloud_aws_services: list[str]
    cloud_azure_subscription_id: str | None
    cloud_azure_tenant_id: str | None
    cloud_azure_client_id: str | None
    cloud_azure_services: list[str]
    # Engagement key is never stored in the config object — resolved at
    # DB-open time via forge.opsec.crypto to avoid lingering in memory.

    @property
    def is_tor_requested(self) -> bool:
        """True if FORGE_PROXY is set to the default Tor SOCKS5 port."""
        return self.proxy == "socks5://127.0.0.1:9050"

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls) -> "ForgeConfig":
        """Resolve configuration from environment variables."""
        data_dir = Path(os.environ.get("FORGE_DATA_DIR", _DEFAULT_DATA_DIR)).expanduser()
        data_dir.mkdir(parents=True, exist_ok=True)

        log_level_raw = os.environ.get("FORGE_LOG_LEVEL", "INFO").upper()
        if log_level_raw not in _VALID_LOG_LEVELS:
            _LOG.warning("Invalid FORGE_LOG_LEVEL=%r; defaulting to INFO.", log_level_raw)
            log_level_raw = "INFO"
        logging.basicConfig(level=getattr(logging, log_level_raw))

        offline_strict = os.environ.get("FORGE_OFFLINE_STRICT", "0").strip() == "1"
        safe_mode = os.environ.get("FORGE_SAFE_MODE", "0").strip() in ("1", "true", "yes")

        operator = os.environ.get("FORGE_OPERATOR") or _get_os_username()

        curl_profile = os.environ.get("FORGE_CURL_IMPERSONATE", "chrome120")
        if curl_profile not in _VALID_CURL_PROFILES:
            _LOG.warning("Unknown FORGE_CURL_IMPERSONATE=%r; using chrome120.", curl_profile)
            curl_profile = "chrome120"

        proxy = os.environ.get("FORGE_PROXY") or None
        supabase_auto_discovery = os.environ.get("FORGE_SUPABASE_AUTO_DISCOVERY", "1").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        mobile_assets_scan = os.environ.get("FORGE_MOBILE_ASSETS_SCAN", "1").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        repo_key_scavenge = os.environ.get("FORGE_REPO_KEY_SCAVENGE", "1").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        firebase_web_discovery = os.environ.get("FORGE_FIREBASE_WEB_DISCOVERY", "1").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        firebase_repo_scavenge = os.environ.get("FORGE_FIREBASE_REPO_SCAVENGE", "1").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        web_enabled = os.environ.get("FORGE_WEB_ENABLED", "0").strip() in ("1", "true", "yes", "on")
        web_host = os.environ.get("FORGE_WEB_HOST", "127.0.0.1").strip() or "127.0.0.1"
        web_port_raw = os.environ.get("FORGE_WEB_PORT", "8080").strip()
        web_port = int(web_port_raw) if web_port_raw.isdigit() else 8080
        web_auth = os.environ.get("FORGE_WEB_AUTH", "jwt").strip() or "jwt"
        web_secret_key = os.environ.get("FORGE_WEB_SECRET_KEY", "")
        if (
            web_enabled
            and web_auth.lower() == "jwt"
            and not web_secret_key
            and not _is_dev_profile()
        ):
            raise RuntimeError("FORGE_WEB_SECRET_KEY must be set when FORGE_WEB_ENABLED=1.")
        distributed_enabled = os.environ.get("FORGE_DISTRIBUTED_ENABLED", "0").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        redis_url = os.environ.get("FORGE_REDIS_URL") or None
        max_workers_raw = os.environ.get("FORGE_MAX_WORKERS", "4").strip()
        max_workers = int(max_workers_raw) if max_workers_raw.isdigit() else 4
        task_timeout_raw = os.environ.get("FORGE_TASK_TIMEOUT", "3600").strip()
        task_timeout = int(task_timeout_raw) if task_timeout_raw.isdigit() else 3600
        browser_headless = os.environ.get("FORGE_BROWSER_HEADLESS", "1").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        browser_timeout_raw = os.environ.get("FORGE_BROWSER_TIMEOUT", "30").strip()
        browser_timeout = int(browser_timeout_raw) if browser_timeout_raw.isdigit() else 30
        screenshot_enabled = os.environ.get("FORGE_SCREENSHOT_ENABLED", "1").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        cdn_detection = os.environ.get("FORGE_CDN_DETECTION", "1").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        waf_detection = os.environ.get("FORGE_WAF_DETECTION", "1").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        shodan_key = (
            os.environ.get("FORGE_SHODAN_API_KEY") or os.environ.get("FORGE_SHODAN_KEY") or None
        )
        auth_max_attempts_raw = os.environ.get("FORGE_AUTH_MAX_ATTEMPTS", "1000").strip()
        auth_max_attempts = int(auth_max_attempts_raw) if auth_max_attempts_raw.isdigit() else 1000
        auth_rate_limit_raw = os.environ.get("FORGE_AUTH_RATE_LIMIT", "10").strip()
        auth_rate_limit = int(auth_rate_limit_raw) if auth_rate_limit_raw.isdigit() else 10
        c2_default_channel = (
            os.environ.get("FORGE_C2_DEFAULT_CHANNEL", "https").strip().lower() or "https"
        )
        if c2_default_channel not in {"https", "dns", "smb", "icmp"}:
            _LOG.warning(
                "Invalid FORGE_C2_DEFAULT_CHANNEL=%r; defaulting to https.", c2_default_channel
            )
            c2_default_channel = "https"
        c2_fallback_order_raw = os.environ.get(
            "FORGE_C2_FALLBACK_ORDER", "https,dns,smb,icmp"
        ).strip()
        c2_fallback_order = [
            item.strip().lower() for item in c2_fallback_order_raw.split(",") if item.strip()
        ]
        if not c2_fallback_order:
            c2_fallback_order = ["https", "dns", "smb", "icmp"]
        valid_channels = {"https", "dns", "smb", "icmp"}
        if any(ch not in valid_channels for ch in c2_fallback_order):
            _LOG.warning(
                "Invalid FORGE_C2_FALLBACK_ORDER=%r; defaulting to https,dns,smb,icmp.",
                c2_fallback_order_raw,
            )
            c2_fallback_order = ["https", "dns", "smb", "icmp"]
        c2_failure_threshold_https_raw = os.environ.get(
            "FORGE_C2_FAIL_THRESHOLD_HTTPS", "3"
        ).strip()
        c2_failure_threshold_dns_raw = os.environ.get("FORGE_C2_FAIL_THRESHOLD_DNS", "3").strip()
        c2_failure_threshold_smb_raw = os.environ.get("FORGE_C2_FAIL_THRESHOLD_SMB", "2").strip()
        c2_failure_threshold_icmp_raw = os.environ.get("FORGE_C2_FAIL_THRESHOLD_ICMP", "2").strip()
        c2_failure_threshold_https = (
            int(c2_failure_threshold_https_raw) if c2_failure_threshold_https_raw.isdigit() else 3
        )
        c2_failure_threshold_dns = (
            int(c2_failure_threshold_dns_raw) if c2_failure_threshold_dns_raw.isdigit() else 3
        )
        c2_failure_threshold_smb = (
            int(c2_failure_threshold_smb_raw) if c2_failure_threshold_smb_raw.isdigit() else 2
        )
        c2_failure_threshold_icmp = (
            int(c2_failure_threshold_icmp_raw) if c2_failure_threshold_icmp_raw.isdigit() else 2
        )
        c2_smb_pipe_name = os.environ.get("FORGE_C2_SMB_PIPE_NAME", "atsvc").strip() or "atsvc"
        c2_smb_fallback_timeout_raw = os.environ.get("FORGE_C2_SMB_FALLBACK_TIMEOUT", "30").strip()
        c2_smb_fallback_timeout = (
            int(c2_smb_fallback_timeout_raw) if c2_smb_fallback_timeout_raw.isdigit() else 30
        )
        c2_icmp_target_ip = (
            os.environ.get("FORGE_C2_ICMP_TARGET_IP", "127.0.0.1").strip() or "127.0.0.1"
        )
        c2_icmp_packet_interval_raw = os.environ.get("FORGE_C2_ICMP_PACKET_INTERVAL", "180").strip()
        c2_icmp_packet_interval = (
            int(c2_icmp_packet_interval_raw) if c2_icmp_packet_interval_raw.isdigit() else 180
        )
        cloud_aws_profile = os.environ.get("FORGE_AWS_PROFILE") or None
        cloud_aws_regions_raw = os.environ.get("FORGE_AWS_REGIONS", "").strip()
        cloud_aws_regions = [
            item.strip() for item in cloud_aws_regions_raw.split(",") if item.strip()
        ]
        cloud_aws_services_raw = os.environ.get(
            "FORGE_AWS_SERVICES", "iam,s3,rds,ec2,lambda,cloudtrail"
        ).strip()
        cloud_aws_services = [
            item.strip().lower() for item in cloud_aws_services_raw.split(",") if item.strip()
        ]
        cloud_azure_subscription_id = os.environ.get("FORGE_AZURE_SUBSCRIPTION_ID") or None
        cloud_azure_tenant_id = os.environ.get("FORGE_AZURE_TENANT_ID") or None
        cloud_azure_client_id = os.environ.get("FORGE_AZURE_CLIENT_ID") or None
        cloud_azure_services_raw = os.environ.get(
            "FORGE_AZURE_SERVICES", "rbac,storage,sql,keyvault,appservice"
        ).strip()
        cloud_azure_services = [
            item.strip().lower() for item in cloud_azure_services_raw.split(",") if item.strip()
        ]

        kb_path = _env_path("FORGE_KB_PATH") or (data_dir / "knowledge.db")
        nvd_path = _env_path("FORGE_NVD_PATH") or (data_dir / "knowledge.db")
        exploitdb_path = _env_path("FORGE_EXPLOITDB_PATH") or (data_dir / "knowledge.db")
        exploitdb_csv_path = _env_path("FORGE_EXPLOITDB_CSV")

        return cls(
            data_dir=data_dir,
            log_level=log_level_raw,
            offline_strict=offline_strict,
            safe_mode=safe_mode,
            operator=operator,
            kb_path=kb_path,
            nvd_path=nvd_path,
            exploitdb_path=exploitdb_path,
            exploitdb_csv_path=exploitdb_csv_path,
            curl_profile=curl_profile,
            proxy=proxy,
            supabase_auto_discovery=supabase_auto_discovery,
            mobile_assets_scan=mobile_assets_scan,
            repo_key_scavenge=repo_key_scavenge,
            firebase_web_discovery=firebase_web_discovery,
            firebase_repo_scavenge=firebase_repo_scavenge,
            web_enabled=web_enabled,
            web_host=web_host,
            web_port=web_port,
            web_auth=web_auth,
            web_secret_key=web_secret_key,
            distributed_enabled=distributed_enabled,
            redis_url=redis_url,
            max_workers=max_workers,
            task_timeout=task_timeout,
            browser_headless=browser_headless,
            browser_timeout=browser_timeout,
            screenshot_enabled=screenshot_enabled,
            cdn_detection=cdn_detection,
            waf_detection=waf_detection,
            shodan_key=shodan_key,
            auth_max_attempts=auth_max_attempts,
            auth_rate_limit=auth_rate_limit,
            c2_default_channel=c2_default_channel,
            c2_fallback_order=c2_fallback_order,
            c2_failure_threshold_https=c2_failure_threshold_https,
            c2_failure_threshold_dns=c2_failure_threshold_dns,
            c2_failure_threshold_smb=c2_failure_threshold_smb,
            c2_failure_threshold_icmp=c2_failure_threshold_icmp,
            c2_smb_pipe_name=c2_smb_pipe_name,
            c2_smb_fallback_timeout=c2_smb_fallback_timeout,
            c2_icmp_target_ip=c2_icmp_target_ip,
            c2_icmp_packet_interval=c2_icmp_packet_interval,
            cloud_aws_profile=cloud_aws_profile,
            cloud_aws_regions=cloud_aws_regions,
            cloud_aws_services=cloud_aws_services,
            cloud_azure_subscription_id=cloud_azure_subscription_id,
            cloud_azure_tenant_id=cloud_azure_tenant_id,
            cloud_azure_client_id=cloud_azure_client_id,
            cloud_azure_services=cloud_azure_services,
        )

    # ------------------------------------------------------------------
    # Derived paths
    # ------------------------------------------------------------------

    def engagement_db_path(self, engagement_id: str) -> Path:
        """Return the age-encrypted engagement DB path for a given engagement ID."""
        safe_id = _sanitise_id(engagement_id)
        primary = self.data_dir / "engagements" / f"{safe_id}.db"
        primary.parent.mkdir(parents=True, exist_ok=True)
        if primary.exists():
            return primary
        legacy_root = Path.cwd() / ".forge_data" / "engagements"
        legacy = legacy_root / f"{safe_id}.db"
        if legacy.exists():
            return legacy
        return primary

    def staging_dir(self, engagement_id: str) -> Path:
        """Return the obfuscated staging directory (exfiltrated_data/ → staging/)."""
        safe_id = _sanitise_id(engagement_id)
        return self.data_dir / "engagements" / safe_id / "staging"

    def sessions_dir(self, engagement_id: str) -> Path:
        """Return the obfuscated sessions directory (agents/ → sessions/)."""
        safe_id = _sanitise_id(engagement_id)
        return self.data_dir / "engagements" / safe_id / "sessions"

    def templates_dir(self, engagement_id: str) -> Path:
        """Return the obfuscated templates directory (payloads/ → templates/)."""
        safe_id = _sanitise_id(engagement_id)
        return self.data_dir / "engagements" / safe_id / "templates"


# ---------------------------------------------------------------------------
# Safe-mode gate
# ---------------------------------------------------------------------------


def is_offensive_enabled() -> bool:
    """Return True if offensive modules (Phase 3 payloads, Phase 5 post-exploitation) are allowed.

    This reads ``FORGE_SAFE_MODE`` directly from the environment so it can be
    called before a full :class:`ForgeConfig` is instantiated (e.g. at import
    time in ``__init__.py`` modules).
    """
    return os.environ.get("FORGE_SAFE_MODE", "0").strip() not in ("1", "true", "yes")


class SafeModeError(RuntimeError):
    """Raised when an offensive module is accessed while FORGE_SAFE_MODE=1."""

    def __init__(self, module_name: str) -> None:
        super().__init__(
            f"[FORGE_SAFE_MODE] {module_name} is disabled in safe mode. "
            "Set FORGE_SAFE_MODE=0 (or unset it) to enable offensive modules."
        )


# ---------------------------------------------------------------------------
# Runtime safe-mode toggle
# ---------------------------------------------------------------------------


def upsert_env_file(key: str, value: str, env_path: Path) -> None:
    """Insert or update *key*=*value* in a ``.env`` file.

    Preserves comments, blank lines, and ordering.  Creates the file if it
    does not exist.
    """
    lines: list[str] = []
    found = False
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith(f"{key}=") or stripped.startswith(f"{key} ="):
                lines[i] = f"{key}={value}\n"
                found = True
                break
    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(f"{key}={value}\n")
    env_path.write_text("".join(lines), encoding="utf-8")


def prompt_offensive_upgrade(phase_label: str = "Offensive modules") -> bool:
    """Interactively offer to install offensive deps and disable safe mode.

    Returns ``True`` when the upgrade succeeded and the caller should
    continue with the originally-requested operation.  Returns ``False``
    when the operator declined or the install failed.
    """
    import subprocess as _sp  # noqa: PLC0415
    import sys as _sys  # noqa: PLC0415

    import questionary  # noqa: PLC0415
    from rich.console import Console  # noqa: PLC0415

    console = Console(stderr=True)
    console.print(
        f"[bold yellow]SAFE MODE:[/bold yellow] {phase_label} requires offensive "
        "modules, but [bold]FORGE_SAFE_MODE=1[/bold] is currently active."
    )

    confirmed = questionary.confirm(
        "Install offensive dependencies and switch to full-offensive mode now?",
        default=False,
    ).ask()
    if not confirmed:
        return False

    root = Path(__file__).resolve().parent.parent
    req_file = root / "requirements-full.txt"
    if not req_file.exists():
        console.print(f"[bold red]ERROR:[/bold red] requirements-full.txt not found at {req_file}.")
        return False

    console.print("[bold cyan]Installing offensive dependencies...[/bold cyan]")
    result = _sp.run(
        [_sys.executable, "-m", "pip", "install", "-r", str(req_file)],
        cwd=str(root),
    )
    if result.returncode != 0:
        console.print("[bold red]ERROR:[/bold red] pip install failed. Safe mode remains active.")
        return False

    os.environ["FORGE_SAFE_MODE"] = "0"

    env_path = root / ".env"
    upsert_env_file("FORGE_SAFE_MODE", "0", env_path)

    console.print(
        "[bold green]OK:[/bold green] Offensive modules enabled. "
        "FORGE_SAFE_MODE=0 persisted to .env. Continuing..."
    )
    return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_os_username() -> str:
    """Return OS username for audit tagging."""
    try:
        import getpass  # noqa: PLC0415

        user = getpass.getuser()
        if user:
            return user
    except Exception:
        pass
    return os.environ.get("USERNAME", os.environ.get("USER", "unknown"))


def _sanitise_id(engagement_id: str) -> str:
    """Strip non-alphanumeric characters to prevent path traversal."""
    import re  # noqa: PLC0415

    sanitised = re.sub(r"[^a-zA-Z0-9_\-]", "_", engagement_id)
    if not sanitised:
        raise ValueError(f"Invalid engagement_id: {engagement_id!r}")
    return sanitised


def _env_path(var_name: str) -> Path | None:
    raw = os.environ.get(var_name)
    if raw is None:
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    return Path(cleaned).expanduser()


def _is_dev_profile() -> bool:
    env_name = os.environ.get("FORGE_ENV", "").strip().lower()
    if env_name in {"dev", "development", "test", "local"}:
        return True
    return os.environ.get("FORGE_WEB_ALLOW_INSECURE_SECRET", "0").strip() in (
        "1",
        "true",
        "yes",
        "on",
    )


def split_secret_values(raw: Optional[str]) -> list[str]:
    if raw is None:
        return []
    values: list[str] = []
    for part in raw.replace("\r", "\n").replace(";", ",").replace("\n", ",").split(","):
        cleaned = part.strip()
        if cleaned:
            values.append(cleaned)
    return values


def resolve_secret_pool(cli_value: Optional[str], env_var_name: str) -> list[str]:
    cli_values = split_secret_values(cli_value)
    if cli_values:
        return cli_values
    return split_secret_values(os.environ.get(env_var_name))


# ---------------------------------------------------------------------------
# Autonomous Platform Configuration (Pydantic BaseSettings)
# ---------------------------------------------------------------------------
# This section extends the existing ForgeConfig with the new autonomous
# platform settings. Uses Pydantic v2 BaseSettings with env-only source
# (no .env auto-load) per Requirements 8.6 and 13.5.
# ---------------------------------------------------------------------------

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class PlatformSettings(BaseSettings):
    """Autonomous security platform configuration.

    All values are sourced exclusively from environment variables.
    No .env file is auto-loaded to maintain OPSEC hygiene (Requirement 8.6).

    Usage::

        settings = PlatformSettings()
    """

    model_config = SettingsConfigDict(
        env_file=None,  # CRITICAL: no .env auto-loading
        env_prefix="FORGE_",
        case_sensitive=False,
    )

    # -- Message Bus ----------------------------------------------------------
    redis_url: str | None = None  # None → in-memory fallback

    # -- State Store ----------------------------------------------------------
    # Default backend: Postgres via the docker-compose dev stack on port 5433.
    # SQLite was the historical default; deployments using SQLite must set
    # FORGE_STATE_DB_URL=sqlite:///path.db explicitly. asyncpg is the only
    # supported Postgres driver - alembic migrations will strip the +asyncpg
    # suffix when invoking sync DDL.
    state_db_url: str = "postgresql+asyncpg://forge:forge_dev_only@localhost:5433/forge"

    # -- Plugin Architecture --------------------------------------------------
    plugin_dir: str = "./plugins"

    # -- Provider Abstraction -------------------------------------------------
    llm_provider: str = "auto"
    llm_model_path: str | None = None  # Required when llm_provider == "llama_cpp"
    provider_timeout: int = 5  # seconds

    # -- Agent Loop -----------------------------------------------------------
    heartbeat_interval: int = 30  # seconds

    # -- Safety Controls ------------------------------------------------------
    safe_mode: int = 0  # 0 = full, 1 = read-only/passive only

    # -- Governance -----------------------------------------------------------
    scope_json: str | None = None  # JSON-encoded engagement scope; required for operations
    governance_rules: str | None = None  # Path to governance policy rules file

    # -- Audit ----------------------------------------------------------------
    # Audit DB is reserved for future structured-audit work; the live audit
    # trail today is the JSONL hash chain in :class:`AuditLogger`. Default
    # is the same Postgres instance to keep ops simple.
    audit_db_url: str = "postgresql+asyncpg://forge:forge_dev_only@localhost:5433/forge"
    telemetry_threshold_ms: int = 5000  # Latency warning threshold

    # -- Message Retry --------------------------------------------------------
    message_retry_max: int = 3
    message_ack_timeout: int = 60  # seconds

    # -- Plugin Executor Hardening (Fix 2/3) ---------------------------------
    # Fix 2 (P0-7): SSRF allowlist override for REST_API plugins.
    allow_private_networks: bool = False
    # Fix 3 (P0-8): Docker resource limits applied unconditionally.
    docker_memory_mb: int = 512  # --memory and --memory-swap value
    docker_cpus: float = 1.0  # --cpus value
    docker_pids_limit: int = 128  # --pids-limit value

    # -- Validators -----------------------------------------------------------

    @field_validator(
        "provider_timeout",
        "heartbeat_interval",
        "telemetry_threshold_ms",
        "message_retry_max",
        "message_ack_timeout",
        mode="before",
    )
    @classmethod
    def _positive_int(cls, v: object) -> int:
        """Ensure numeric settings are positive integers."""
        val = int(v)  # type: ignore[arg-type]
        if val <= 0:
            raise ValueError("Value must be a positive integer")
        return val

    @field_validator("safe_mode", mode="before")
    @classmethod
    def _coerce_safe_mode(cls, v: object) -> int:
        """Accept 0/1 or boolean-like strings for safe_mode."""
        if isinstance(v, str):
            if v.strip().lower() in ("1", "true", "yes", "on"):
                return 1
            return 0
        return int(v)  # type: ignore[arg-type]
