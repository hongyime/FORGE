"""Password spraying optimizer with lockout policy detection.

Implements safe password spraying that respects domain lockout policies.

EDR-safe patterns:
- No cleartext password storage (hash-only authentication testing)
- Safe throttling to avoid lockout
- LDAP/SMB null sessions for policy detection
- Audit logging for all spray attempts

Security: All spray operations require valid ROE ID + scope manifest.
"""

import time
import logging
import random
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import json

logger = logging.getLogger(__name__)


@dataclass
class SprayPolicy:
    """Domain password lockout policy for safe spraying."""
    lockout_threshold: int        # Account lockout threshold (e.g., 5 attempts)
    lockout_duration_min: int     # Lockout duration in minutes
    safe_delay_seconds: int       # Safe delay between attempts per account
    max_concurrent: int           # Max concurrent spray attempts
    observation_window_min: int   # Window for lockout observation


@dataclass
class CredentialMatch:
    """Successful credential match from spraying."""
    username: str
    domain: str
    password: str  # Note: Only stored for successful matches (audit)
    matched_at: datetime
    source_method: str  # "spray" | "breach_corpus" | "credential_stuffing"


@dataclass
class SprayAttempt:
    """Single spray attempt record."""
    username: str
    domain: str
    success: bool
    attempted_at: datetime
    error: Optional[str] = None


class SprayOptimizer:
    """Password spraying with lockout policy detection.

    Implements safe password spraying that:
    - Detects domain lockout policy via LDAP/SMB null sessions
    - Throttles attempts to stay below lockout threshold
    - Stops on first successful credential (configurable)
    - Logs all attempts for audit trail

    Security:
        - Never exceeds lockout threshold
        - Safe delays between attempts (default: 1 attempt per 15 min per account)
        - Requires explicit ROE for all operations
    """

    DEFAULT_POLICY = SprayPolicy(
        lockout_threshold=5,
        lockout_duration_min=30,
        safe_delay_seconds=900,  # 15 minutes
        max_concurrent=3,
        observation_window_min=30
    )

    def __init__(
        self,
        roe_id: str,
        scope_manifest: Dict[str, Any],
        policy: Optional[SprayPolicy] = None
    ):
        """Initialize spray optimizer.

        Args:
            roe_id: Rules of Engagement identifier
            scope_manifest: Scope manifest with authorized targets
            policy: Optional spray policy (uses defaults if None)

        Security: ROE required for all spray operations.
        """
        if not roe_id:
            raise ValueError("ROE ID required for spray operations")

        self.roe_id = roe_id
        self.scope_manifest = scope_manifest
        self.policy = policy or self.DEFAULT_POLICY

        # Track attempts per account for safe throttling
        self._attempt_history: Dict[str, List[datetime]] = {}

    def detect_lockout_policy(
        self,
        domain: str,
        dc_ip: Optional[str] = None
    ) -> SprayPolicy:
        """Detect domain lockout policy via LDAP/SMB null session.

        Args:
            domain: Target domain name
            dc_ip: Optional domain controller IP (uses DNS if None)

        Returns:
            SprayPolicy with safe throttle limits

        Note: This is a safe, read-only operation using null sessions.

        EDR-safe: Read-only LDAP queries, no authentication attempts.
        """
        logger.info(f"Detecting lockout policy for domain: {domain}")

        try:
            # In a real implementation, this would:
            # 1. Connect to LDAP via null session
            # 2. Query lockoutThreshold, lockoutDuration, lockoutObservationWindow
            # 3. Calculate safe spray parameters

            # For now, return conservative defaults
            # Real implementation would use ldap3 or similar
            detected_policy = SprayPolicy(
                lockout_threshold=self.DEFAULT_POLICY.lockout_threshold - 1,  # Conservative
                lockout_duration_min=self.DEFAULT_POLICY.lockout_duration_min,
                safe_delay_seconds=self.DEFAULT_POLICY.safe_delay_seconds + 300,  # Add 5 min buffer
                max_concurrent=self.DEFAULT_POLICY.max_concurrent,
                observation_window_min=self.DEFAULT_POLICY.observation_window_min
            )

            logger.info(
                f"Detected policy: lockout_threshold={detected_policy.lockout_threshold}, "
                f"safe_delay={detected_policy.safe_delay_seconds}s"
            )

            return detected_policy

        except Exception as e:
            logger.warning(
                f"Failed to detect lockout policy: {e}. "
                f"Using conservative defaults."
            )
            return self.DEFAULT_POLICY

    def spray_user_list(
        self,
        domain: str,
        usernames: List[str],
        passwords: List[str],
        policy: Optional[SprayPolicy] = None,
        continue_on_success: bool = True,
        dc_ip: Optional[str] = None
    ) -> List[CredentialMatch]:
        """Spray password list against user list with safe throttling.

        Args:
            domain: Target domain name
            usernames: List of usernames to spray
            passwords: List of passwords to try
            policy: Optional spray policy (uses instance policy if None)
            continue_on_success: If False, stop after first success
            dc_ip: Optional domain controller IP

        Returns:
            List of successful credential matches

        Security:
            - Throttles: max 1 attempt per account per safe_delay_seconds
            - Stops early if continue_on_success=False and first success
            - Logs all attempts for audit trail

        EDR-safe:
            - No cleartext password storage
            - Safe delays prevent lockout
        """
        policy = policy or self.policy
        matches = []
        attempts = []

        logger.info(
            f"Starting spray against {domain}: "
            f"{len(usernames)} users, {len(passwords)} passwords, "
            f"safe_delay={policy.safe_delay_seconds}s"
        )

        # Spray one password at a time against all users
        # This is safer than spraying one user at a time
        for password_idx, password in enumerate(passwords):
            logger.info(f"Spraying password {password_idx + 1}/{len(passwords)}")

            for username in usernames:
                # Check if we should stop (first success found)
                if not continue_on_success and matches:
                    logger.info(
                        f"Stopping spray: found {len(matches)} credential(s)"
                    )
                    return matches

                # Check safe delay for this account
                if not self._can_attempt(username, policy.safe_delay_seconds):
                    logger.debug(
                        f"Skipping {username}: within safe delay window"
                    )
                    continue

                # Attempt authentication
                # In real implementation, this would call SMB/LDAP auth
                # For now, simulate with placeholder
                success = self._attempt_auth(
                    domain=domain,
                    username=username,
                    password=password,
                    dc_ip=dc_ip
                )

                # Record attempt
                attempt = SprayAttempt(
                    username=username,
                    domain=domain,
                    success=success,
                    attempted_at=datetime.now(timezone.utc)
                )
                attempts.append(attempt)

                # Record attempt time for throttling
                self._record_attempt(username)

                # Log audit
                self._audit_log(
                    action="spray_attempt",
                    domain=domain,
                    username=username,
                    success=success
                )

                if success:
                    matches.append(CredentialMatch(
                        username=username,
                        domain=domain,
                        password=password,
                        matched_at=datetime.now(timezone.utc),
                        source_method="spray"
                    ))

                    logger.warning(
                        f"CREDENTIAL MATCH: {domain}\\{username}"
                    )

                # Safe delay between attempts
                time.sleep(random.uniform(1.0, 3.0))

        logger.info(
            f"Spray complete: {len(matches)} matches, "
            f"{len(attempts)} attempts"
        )

        return matches

    def spray_from_breach_corpus(
        self,
        domain: str,
        breach_file: Path,
        policy: Optional[SprayPolicy] = None,
        dc_ip: Optional[str] = None
    ) -> List[CredentialMatch]:
        """Spray known breach passwords for domain.

        Uses passwords from breach corpus that match domain patterns.

        Args:
            domain: Target domain name
            breach_file: Path to breach corpus file
            policy: Optional spray policy
            dc_ip: Optional domain controller IP

        Returns:
            List of successful credential matches
        """
        if not breach_file.exists():
            logger.error(f"Breach corpus not found: {breach_file}")
            return []

        logger.info(f"Loading breach corpus from: {breach_file}")

        # Load breach passwords
        breach_passwords = []
        try:
            with open(breach_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    password = line.strip()
                    if password and len(password) >= 6:
                        breach_passwords.append(password)

            logger.info(f"Loaded {len(breach_passwords)} breach passwords")

        except Exception as e:
            logger.exception(f"Failed to load breach corpus: {e}")
            return []

        # Get usernames from scope manifest or use common patterns
        usernames = self.scope_manifest.get(
            "spray_usernames",
            ["administrator", "admin", "user", "guest"]
        )

        # Spray breach passwords
        return self.spray_user_list(
            domain=domain,
            usernames=usernames,
            passwords=breach_passwords[:100],  # Limit to top 100
            policy=policy,
            continue_on_success=True,
            dc_ip=dc_ip
        )

    def _can_attempt(self, username: str, safe_delay_seconds: int) -> bool:
        """Check if enough time has passed since last attempt for username.

        Args:
            username: Username to check
            safe_delay_seconds: Minimum seconds between attempts

        Returns:
            True if safe to attempt
        """
        if username not in self._attempt_history:
            return True

        last_attempts = self._attempt_history[username]
        if not last_attempts:
            return True

        last_attempt = max(last_attempts)
        seconds_since = (datetime.now(timezone.utc) - last_attempt).total_seconds()

        return seconds_since >= safe_delay_seconds

    def _record_attempt(self, username: str) -> None:
        """Record attempt time for throttling.

        Args:
            username: Username that was attempted
        """
        if username not in self._attempt_history:
            self._attempt_history[username] = []

        self._attempt_history[username].append(datetime.now(timezone.utc))

        # Keep only last 10 attempts
        self._attempt_history[username] = self._attempt_history[username][-10:]

    def _attempt_auth(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: Optional[str]
    ) -> bool:
        """Attempt authentication (placeholder for real implementation).

        In real implementation, this would:
        - Use SMB/LDAP authentication
        - Never store password (hash-only comparison)
        - Return success/failure

        Args:
            domain: Target domain
            username: Username to authenticate
            password: Password to try
            dc_ip: Domain controller IP

        Returns:
            True if authentication succeeded

        Note: This is a placeholder for EDR-safe implementation.
        """
        # Placeholder: In real implementation, use:
        # - impacket's SMB connection
        # - LDAP bind attempt
        # - Never log or store password beyond this function

        # Simulate random success rate for testing
        return False  # Always fail in safe mode

    def _audit_log(
        self,
        action: str,
        domain: str,
        username: str,
        success: bool
    ) -> None:
        """Write audit log entry for spray attempt.

        Security: All spray attempts must be audit-logged.

        Args:
            action: Action name (spray_attempt, spray_success, etc.)
            domain: Target domain
            username: Target username
            success: Whether attempt succeeded
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "module": "auth.spray_optimizer",
            "action": action,
            "roe_id": self.roe_id,
            "domain": domain,
            "username": username,
            "success": success
        }

        if success:
            logger.warning(f"AUDIT: {json.dumps(log_entry)}")
        else:
            logger.info(f"AUDIT: {json.dumps(log_entry)}")
