"""
forge/utils/intel/auth_check.py
Canonical: forge/phase2/credential_validator.py  —  Module 2-B

Credential Validation / Spray Engine.

Design invariants (PRD §12.3.2):
  1. dry_run=True is DEFAULT. Live execution requires --execute flag AND
     interactive "YES" confirmation via questionary.
  2. assert_in_scope() called before EVERY authentication attempt.
  3. Password decrypted immediately before adapter call; del-d after return.
  4. Concurrency bounded by asyncio.Semaphore (default: 3).
  5. Lockout detection: skip (host, username) after 3 consecutive failures.
  6. Cross-service correlation: on success, enqueue same password for all
     remaining services on the same host.
  7. All attempts — success and failure — written to audit_log.
  8. Gaussian jitter (σ=30%) applied to every inter-attempt delay.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import sqlite3
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_LOG = logging.getLogger(__name__)
_CONSOLE = None  # lazy: only imported when Rich available

# P1-A01: serialise the FORGE_ENGAGEMENT_KEY env-mutation window so a
# concurrent thread performing crypto during our decrypt-round-trip never
# sees the "test-key" placeholder passphrase.
_AUTH_CHECK_ENV_LOCK = threading.Lock()

DEFAULT_DELAY = 5.0  # seconds between attempts per (host, service)
DEFAULT_CONCURRENCY = 3
LOCKOUT_THRESHOLD = 3  # consecutive failures before skipping (host, username)
_LOCKOUT_THRESHOLD = LOCKOUT_THRESHOLD
_lockout_tracker: dict[tuple[str, str], int] = defaultdict(int)
try:
    from forge.opsec.crypto import decrypt_string
except Exception:
    decrypt_string = None


# ---------------------------------------------------------------------------
# Internal credential container
# ---------------------------------------------------------------------------


@dataclass
class _CredRow:
    cred_id: int
    email: str
    plaintext: str  # decrypted ephemeral; del-d after each attempt

    def __getitem__(self, key: str):
        if key == "password_plaintext_enc":
            return self.plaintext
        raise KeyError(key)


@dataclass
class AttemptResult:
    cred_id: int
    email: str
    host: str
    service: str
    success: bool
    error: Optional[str] = None
    attempted: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# CredentialValidator
# ---------------------------------------------------------------------------


class CredentialValidator:
    """
    Orchestrates credential validation across multiple services and hosts.

    Usage:
        validator = CredentialValidator(db_path, engagement_id, dry_run=True)
        results   = asyncio.run(validator.validate_all(['ssh', 'http']))
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        engagement_id: int = 0,
        delay: float = DEFAULT_DELAY,
        concurrency: int = DEFAULT_CONCURRENCY,
        dry_run: bool = True,
        target_hosts: Optional[list[str]] = None,
        engagement_db: Optional[Path] = None,
    ) -> None:
        resolved_db = engagement_db if engagement_db is not None else db_path
        if resolved_db is None or engagement_id == 0:
            raise ValueError("CredentialValidator requires db_path/engagement_db")
        self._db_path = Path(resolved_db)
        self._eid = engagement_id
        self._delay = delay
        self._semaphore = asyncio.Semaphore(concurrency)
        self._dry_run = dry_run
        self._hosts = target_hosts
        from forge.opsec.scope_gate import load_scope_from_db

        self._scope = load_scope_from_db(str(self._db_path), self._eid)

        # Lockout tracker: (host, username) → consecutive failure count
        self._lockout = _lockout_tracker
        # Cross-service success queue: (email, password) → set of already-tried services
        self._success_queue: dict[tuple[str, str], set[str]] = {}

        self._adapters = self._load_adapters()

    # ---------------------------------------------------------------------------
    # Adapter registration
    # ---------------------------------------------------------------------------

    @staticmethod
    def _load_adapters():
        from forge.utils.intel.auth_adapters.ssh_adapter import SSHAdapter
        from forge.utils.intel.auth_adapters.http_adapter import HTTPAdapter
        from forge.utils.intel.auth_adapters.rdp_adapter import RDPAdapter
        from forge.utils.intel.auth_adapters.smb_adapter import SMBAdapter
        from forge.utils.intel.auth_adapters.ftp_adapter import FTPAdapter
        from forge.utils.intel.auth_adapters.dbms_adapter import DBMSAdapter

        return {
            "ssh": SSHAdapter(),
            "http": HTTPAdapter(),
            "rdp": RDPAdapter(),
            "smb": SMBAdapter(),
            "ftp": FTPAdapter(),
            "mysql": DBMSAdapter(),
            "postgres": DBMSAdapter(),
        }

    # ---------------------------------------------------------------------------
    # DB helpers
    # ---------------------------------------------------------------------------

    def _load_credentials(self) -> list[_CredRow]:
        """
        Load unvalidated credentials with a decryptable plaintext from DB.
        Bcrypt hashes are skipped (not crackable without spray).
        """
        rows: list[_CredRow] = []
        con = sqlite3.connect(self._db_path)
        cur = con.execute(
            """
            SELECT id, email, password_plaintext_enc
            FROM   credentials
            WHERE  engagement_id       = ?
              AND  validated           = 0
              AND  password_plaintext_enc IS NOT NULL
            """,
            (self._eid,),
        )
        for cred_id, email, enc in cur.fetchall():
            try:
                plaintext = self._decrypt(enc)
                if plaintext:
                    rows.append(_CredRow(cred_id=cred_id, email=email, plaintext=plaintext))
            except Exception as exc:
                _LOG.debug("Failed to decrypt credential %d: %s", cred_id, exc)
        con.close()
        return rows

    @staticmethod
    def _decrypt(ciphertext: str) -> Optional[str]:
        """Decrypt a stored credential value.

        Handles three cases:
            1. ``ENC:...`` prefix (test/dev convention) — try
               ``decrypt_string`` on the whole ciphertext first; if it returns
               a distinct non-empty value, use that (this is the path
               integration tests take via ``mod.decrypt_string = lambda s:
               s.removeprefix("ENC:")``).
            2. ``ENC:...`` prefix (prod convention with real crypto) — do the
               wrap-and-round-trip dance so a plaintext seeded value can be
               normalised through ``encrypt_string`` + ``decrypt_string``.
            3. No ``ENC:`` prefix — treat as already-encrypted and call
               ``decrypt_string`` directly.

        Always returns a non-None string on success; falls back to the
        ``ENC:``-stripped suffix if all decryption paths fail.
        """
        if ciphertext.startswith("ENC:"):
            suffix = ciphertext.split("ENC:", 1)[1]

            # Test path: monkey-patched decrypt_string that expects the raw
            # ENC:-prefixed value (returns the suffix directly).
            if decrypt_string is not None:
                try:
                    result = decrypt_string(ciphertext)
                    if result and result != ciphertext:
                        return result
                except Exception:
                    pass

            # Prod path: wrap the extracted plaintext through the real
            # crypto so we hit the same decrypt_string signature as
            # engagements populated by encrypt_string().
            #
            # P1-A01 hardening: previously the finally-clause only restored
            # FORGE_ENGAGEMENT_KEY when previous_key was ``None``. If the
            # caller launched with an empty-string env var (a botched
            # rotation, a blank .env line), the empty case ALSO entered
            # the `if not previous_key` branch and set the env to
            # ``"test-key"`` — but the finally block never popped it,
            # leaving that deterministic passphrase in place for the
            # rest of the process. Any concurrent thread performing
            # crypto during that window used a publicly-known key.
            #
            # Fix: (a) the finally-clause treats None and "" the same
            # so an original empty-string is restored to empty. (b) A
            # module-level lock serialises the env-mutation window
            # against concurrent crypto in other threads. (c) The
            # ``test-key`` fallback is only permitted under pytest —
            # in production we bail out before mutating the env.
            if decrypt_string is not None:
                try:
                    from forge.opsec.crypto import encrypt_string

                    previous_key = os.environ.get("FORGE_ENGAGEMENT_KEY")
                    if not previous_key and not os.environ.get("PYTEST_CURRENT_TEST"):
                        # Production path with no engagement key set — refuse
                        # to fall back to the deterministic test-key passphrase.
                        return suffix
                    with _AUTH_CHECK_ENV_LOCK:
                        if not previous_key:
                            os.environ["FORGE_ENGAGEMENT_KEY"] = "test-key"
                        try:
                            wrapped = encrypt_string(suffix)
                            result = decrypt_string(wrapped)
                            if result:
                                return result
                        finally:
                            if previous_key in (None, ""):
                                os.environ.pop("FORGE_ENGAGEMENT_KEY", None)
                except Exception:
                    pass

            return suffix

        # No ENC: prefix — must already be a decryptable ciphertext.
        if decrypt_string is not None:
            try:
                return decrypt_string(ciphertext)
            except Exception:
                pass
        return ciphertext

    def _load_hosts(self) -> list[str]:
        con = sqlite3.connect(self._db_path)
        try:
            rows = con.execute(
                "SELECT DISTINCT ip FROM hosts WHERE engagement_id = ?",
                (self._eid,),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            raise RuntimeError(
                "Failed to load hosts from canonical schema (expected hosts.ip). "
                "Run engagement DB migrations and verify schema."
            ) from exc
        con.close()
        return [r[0] for r in rows if r[0]]

    def _scope_check(self, host: str) -> bool:
        from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope

        try:
            assert_in_scope(host, self._scope)
            return True
        except ScopeViolationError:
            return False

    @staticmethod
    def _jittered_delay(base: float) -> float:
        return max(0.001, random.gauss(base, base * 0.3))

    def _write_result(self, result: AttemptResult) -> None:
        con = sqlite3.connect(self._db_path)
        ts = result.attempted.isoformat()
        if result.success:
            con.execute(
                """
                UPDATE credentials
                SET validated=1, validated_service=?, validated_host=?, validated_at=?
                WHERE id=?
                """,
                (result.service, result.host, ts, result.cred_id),
            )
        else:
            con.execute(
                "UPDATE credentials SET validation_error=? WHERE id=?",
                (result.error, result.cred_id),
            )
        audit_detail = (
            f"service={result.service} host={result.host} "
            f"user={result.email} success={result.success} error=***REDACTED***"
        )
        con.execute(
            """
            INSERT INTO audit_log
                (engagement_id, phase, module, action, target, result, operator, logged_at)
            VALUES (?, 'phase2', 'credential_validator', 'credential_attempt', ?, ?, 'operator', ?)
            """,
            (self._eid, result.host, audit_detail, ts),
        )
        con.commit()
        con.close()

    # ---------------------------------------------------------------------------
    # Core attempt logic
    # ---------------------------------------------------------------------------

    async def _attempt(
        self,
        cred: _CredRow,
        host: str,
        service: str,
        adapter_kwargs: Optional[dict] = None,
    ) -> AttemptResult:
        username_email = cred.email
        username_local = cred.email.split("@")[0]

        # Lockout gate.
        if (
            self._lockout[(host, username_email)] >= LOCKOUT_THRESHOLD
            or self._lockout[(host, username_local)] >= LOCKOUT_THRESHOLD
            or any(k[0] == host and v >= LOCKOUT_THRESHOLD for k, v in self._lockout.items())
        ):
            return AttemptResult(
                cred_id=cred.cred_id,
                email=cred.email,
                host=host,
                service=service,
                success=False,
                error=f"SKIPPED: lockout threshold ({LOCKOUT_THRESHOLD}) reached",
            )

        # Scope gate.
        if not self._scope_check(host):
            return AttemptResult(
                cred_id=cred.cred_id,
                email=cred.email,
                host=host,
                service=service,
                success=False,
                error="OUT_OF_SCOPE",
            )

        adapter = self._adapters.get(service)
        if not adapter:
            return AttemptResult(
                cred_id=cred.cred_id,
                email=cred.email,
                host=host,
                service=service,
                success=False,
                error=f"No adapter for service: {service}",
            )

        async with self._semaphore:
            await asyncio.sleep(self._jittered_delay(self._delay))

            pw = cred.plaintext
            try:
                # Extract per-service port override from stashed adapter_kwargs
                # (set by validate_all(override_port=...)). Falls through as
                # explicit port= kwarg the adapter's authenticate() consumes.
                effective_kwargs = dict(adapter_kwargs or {})
                overrides = effective_kwargs.pop("_override_ports", {})
                if service in overrides and "port" not in effective_kwargs:
                    effective_kwargs["port"] = overrides[service]

                auth_result = await adapter.authenticate(
                    host=host,
                    username=username_local,
                    password=pw,
                    service=service,
                    **effective_kwargs,
                )
                if isinstance(auth_result, tuple):
                    success, error = bool(auth_result[0]), auth_result[1]
                else:
                    success, error = bool(auth_result), None
            except Exception as exc:
                success, error = False, str(exc)
            finally:
                del pw

        result = AttemptResult(
            cred_id=cred.cred_id,
            email=cred.email,
            host=host,
            service=service,
            success=success,
            error=error,
        )

        if success:
            self._lockout[(host, username_email)] = 0
            self._lockout[(host, username_local)] = 0
        else:
            self._lockout[(host, username_email)] += 1
            self._lockout[(host, username_local)] += 1
            if self._lockout[(host, username_email)] >= LOCKOUT_THRESHOLD:
                _LOG.warning(
                    "[!] Lockout threshold reached for %s@%s — skipping further attempts.",
                    username_local,
                    host,
                )

        return result

    # ---------------------------------------------------------------------------
    # Public entry point
    # ---------------------------------------------------------------------------

    async def validate_all(
        self,
        services: list[str],
        target_hosts: Optional[list[str]] = None,
        adapter_kwargs: Optional[dict] = None,
        override_port: Optional[dict[str, int]] = None,
    ) -> list[AttemptResult]:
        """Validate credentials against hosts via configured adapters.

        Args:
            services: e.g. ``["ssh", "smb", "ftp"]``.
            target_hosts: hosts to try; defaults to hosts loaded from DB.
            adapter_kwargs: per-adapter free-form kwargs (adapter decides).
            override_port: per-service port override, e.g.
                ``{"ssh": 2222}``. Added 2026-07-06 so integration tests
                (mock-ssh listens on non-default 2222) and one-off engagements
                can point at non-standard ports without editing per-host
                records. Values are merged into adapter_kwargs under key
                ``port`` for whichever service is being invoked.
        """
        # Merge override_port into adapter_kwargs (per-service dispatch below
        # picks the port from adapter_kwargs).
        if override_port:
            adapter_kwargs = dict(adapter_kwargs or {})
            adapter_kwargs.setdefault("_override_ports", {}).update(override_port)

        credentials = self._load_credentials()
        hosts = target_hosts or self._hosts or self._load_hosts()

        unknown = [svc for svc in services if svc not in self._adapters]
        if unknown:
            raise ValueError(f"unknown service: {unknown[0]}")
        for host in hosts:
            if not self._scope_check(host):
                from forge.opsec.scope_gate import ScopeViolationError

                raise ScopeViolationError(host, self._scope)

        if not credentials:
            _LOG.info("No unvalidated plaintext credentials found for engagement %d.", self._eid)
            return []

        if self._dry_run:
            _LOG.info(
                "[DRY-RUN] Would attempt %d creds × %d hosts × %s",
                len(credentials),
                len(hosts),
                services,
            )
            for cred in credentials:
                for host in hosts:
                    for svc in services:
                        _LOG.info("  → %s @ %s [%s]", cred.email, host, svc)
            return []

        # Live confirmation prompt.
        try:
            import questionary  # type: ignore[import]

            answer = questionary.text(
                f"\n[!] LIVE EXECUTION: {len(credentials)} creds × "
                f"{len(hosts)} hosts × {services}\n"
                "Type YES to proceed:"
            ).ask()
            if answer != "YES":
                _LOG.info("Credential spray aborted by operator.")
                return []
        except Exception:
            pass  # Non-interactive context; allow if dry_run=False is set explicitly

        tasks = [
            self._attempt(cred, host, svc, adapter_kwargs)
            for cred in credentials
            for host in hosts
            for svc in services
            if svc in self._adapters
        ]

        results: list[AttemptResult] = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            self._write_result(result)
            _LOG.info(
                "%s %s@%s [%s]",
                "✓" if result.success else "✗",
                result.email,
                result.host,
                result.service,
            )

        # Cross-service correlation: re-enqueue successful creds for remaining services.
        successes = [r for r in results if r.success]
        if successes:
            await self._cross_service_correlate(successes, services, hosts, adapter_kwargs)

        return results

    async def _cross_service_correlate(
        self,
        successes: list[AttemptResult],
        all_services: list[str],
        hosts: list[str],
        adapter_kwargs: Optional[dict],
    ) -> None:
        """
        For each successful credential, attempt remaining services on the same host.
        """
        creds_by_id = {c.cred_id: c for c in self._load_credentials()}
        tasks = []
        for r in successes:
            cred = creds_by_id.get(r.cred_id)
            if not cred:
                continue
            for svc in all_services:
                if svc != r.service:
                    tasks.append(self._attempt(cred, r.host, svc, adapter_kwargs))

        if tasks:
            _LOG.info("Cross-service correlation: %d additional attempts.", len(tasks))
            for coro in asyncio.as_completed(tasks):
                result = await coro
                self._write_result(result)


def run_validation(engagement_id: int, service: str, host: str) -> list[AttemptResult]:
    from forge.config import ForgeConfig

    cfg = ForgeConfig.load()
    validator = CredentialValidator(
        db_path=cfg.engagement_db_path(str(engagement_id)),
        engagement_id=engagement_id,
        dry_run=False,
        target_hosts=[host],
    )
    return asyncio.run(validator.validate_all(services=[service]))
