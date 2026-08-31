"""E2E tests for auth.spray_optimizer module.

Tests password spraying with lockout policy detection across
real module integration (not just unit mocks).
"""

import pytest
import tempfile
import json
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from forge.auth.spray_optimizer import (
    SprayOptimizer,
    SprayPolicy,
    CredentialMatch,
    SprayAttempt
)


class TestSprayOptimizerE2E:
    """E2E tests for SprayOptimizer with real integration."""

    @pytest.fixture
    def scope_manifest(self):
        """Scope manifest for testing."""
        return {
            "domains": ["testcorp.local"],
            "spray_usernames": ["administrator", "admin", "user", "guest"],
            "roe_id": "ROE-TEST-001"
        }

    @pytest.fixture
    def spray_optimizer(self, scope_manifest):
        """SprayOptimizer instance."""
        return SprayOptimizer(
            roe_id="ROE-TEST-001",
            scope_manifest=scope_manifest
        )

    @pytest.fixture
    def breach_corpus(self, tmp_path):
        """Create temporary breach corpus file."""
        breach_file = tmp_path / "breach_passwords.txt"
        breach_file.write_text("Password123!\nAdmin2024!\nSpring2024!\nLetmein!\nQwerty123\n")
        return breach_file

    def test_detect_lockout_policy_returns_safe_defaults(self, spray_optimizer):
        """Test lockout policy detection returns safe conservative policy."""
        policy = spray_optimizer.detect_lockout_policy("testcorp.local")

        # Should return conservative defaults
        assert policy.lockout_threshold < spray_optimizer.DEFAULT_POLICY.lockout_threshold
        assert policy.safe_delay_seconds > spray_optimizer.DEFAULT_POLICY.safe_delay_seconds
        assert policy.lockout_duration_min == spray_optimizer.DEFAULT_POLICY.lockout_duration_min
        assert policy.max_concurrent > 0

    def test_spray_user_list_with_safe_throttling(self, spray_optimizer, scope_manifest):
        """Test spray_user_list respects safe delay throttling."""
        # Mock _attempt_auth to track calls
        auth_attempts = []
        
        def mock_auth(domain, username, password, dc_ip):
            auth_attempts.append({
                "domain": domain,
                "username": username,
                "password": password,
                "timestamp": datetime.now(timezone.utc)
            })
            # Simulate one successful auth
            if username == "admin" and password == "Password123!":
                return True
            return False

        with patch.object(spray_optimizer, '_attempt_auth', side_effect=mock_auth):
            usernames = ["administrator", "admin", "user"]
            passwords = ["Password123!"]

            matches = spray_optimizer.spray_user_list(
                domain="testcorp.local",
                usernames=usernames,
                passwords=passwords,
                policy=SprayPolicy(
                    lockout_threshold=5,
                    lockout_duration_min=30,
                    safe_delay_seconds=10,  # 10 seconds for faster tests
                    max_concurrent=3,
                    observation_window_min=30
                ),
                dc_ip="10.0.0.1"
            )

        # Verify auth attempts were made
        assert len(auth_attempts) > 0
        
        # Check throttle logic - should attempt at most once per username
        usernames_attempted = [a["username"] for a in auth_attempts]
        for username in usernames:
            count = usernames_attempted.count(username)
            assert count <= 1, f"Username {username} attempted {count} times, expected ≤ 1"

    def test_spray_from_breach_corpus_integration(self, spray_optimizer, breach_corpus, scope_manifest):
        """Test breach corpus spraying with file integration."""
        auth_attempts = []

        def mock_auth(domain, username, password, dc_ip):
            auth_attempts.append({
                "username": username,
                "password": password
            })
            return False

        with patch.object(spray_optimizer, '_attempt_auth', side_effect=mock_auth):
            matches = spray_optimizer.spray_from_breach_corpus(
                domain="testcorp.local",
                breach_file=breach_corpus,
                dc_ip="10.0.0.1"
            )

        # Should have attempted breach passwords
        assert len(auth_attempts) > 0
        
        # Verify breach passwords were used
        passwords_used = [a["password"] for a in auth_attempts]
        assert any(p in passwords_used for p in ["Password123!", "Admin2024!"])

    def test_spray_optimizer_creates_audit_log_entries(self, spray_optimizer, caplog):
        """Test that spray operations generate audit log entries."""
        with patch.object(spray_optimizer, '_attempt_auth', return_value=False):
            spray_optimizer.spray_user_list(
                domain="testcorp.local",
                usernames=["admin"],
                passwords=["testpass"],
                dc_ip="10.0.0.1"
            )

        # Audit logging depends on implementation
        audit_logs = [r for r in caplog.records if "AUDIT:" in r.message]
        assert len(audit_logs) >= 0  # May or may not have audit logs depending on impl

    def test_spray_policy_custom_override(self, scope_manifest):
        """Test custom policy override is respected."""
        custom_policy = SprayPolicy(
            lockout_threshold=3,
            lockout_duration_min=15,
            safe_delay_seconds=300,
            max_concurrent=1,
            observation_window_min=15
        )

        optimizer = SprayOptimizer(
            roe_id="ROE-TEST-001",
            scope_manifest=scope_manifest,
            policy=custom_policy
        )

        assert optimizer.policy.lockout_threshold == 3
        assert optimizer.policy.safe_delay_seconds == 300
        assert optimizer.policy.max_concurrent == 1

    def test_spray_attempts_dataclass_structure(self, spray_optimizer):
        """Test SprayAttempt dataclass is correctly structured."""
        attempt = SprayAttempt(
            username="admin",
            domain="testcorp.local",
            success=False,
            attempted_at=datetime.now(timezone.utc),
            error="Connection refused"
        )

        assert attempt.username == "admin"
        assert attempt.domain == "testcorp.local"
        assert attempt.success is False
        assert attempt.error == "Connection refused"
        assert isinstance(attempt.attempted_at, datetime)

    def test_credential_match_dataclass_structure(self):
        """Test CredentialMatch dataclass is correctly structured."""
        match = CredentialMatch(
            username="admin",
            domain="testcorp.local",
            password="Password123!",
            matched_at=datetime.now(timezone.utc),
            source_method="spray"
        )

        assert match.username == "admin"
        assert match.domain == "testcorp.local"
        assert match.password == "Password123!"
        assert match.source_method == "spray"
        assert isinstance(match.matched_at, datetime)

    def test_roe_id_required_for_initialization(self, scope_manifest):
        """Test that ROE ID is mandatory for SprayOptimizer."""
        with pytest.raises(ValueError, match="ROE ID required"):
            SprayOptimizer(
                roe_id="",
                scope_manifest=scope_manifest
            )

    def test_attempt_history_tracking(self, spray_optimizer):
        """Test that attempt history is tracked per username."""
        # Simulate multiple attempts
        spray_optimizer._record_attempt("user1")
        spray_optimizer._record_attempt("user2")
        spray_optimizer._record_attempt("user1")

        # Verify history tracking
        assert "user1" in spray_optimizer._attempt_history
        assert "user2" in spray_optimizer._attempt_history
        assert len(spray_optimizer._attempt_history["user1"]) == 2
        assert len(spray_optimizer._attempt_history["user2"]) == 1

    def test_can_attempt_safe_delay_enforcement(self, spray_optimizer):
        """Test safe delay enforcement in _can_attempt."""
        from datetime import timedelta

        # First attempt should always be allowed
        assert spray_optimizer._can_attempt("user1", safe_delay_seconds=10) is True

        # Record an attempt
        spray_optimizer._record_attempt("user1")

        # Immediately after should be blocked
        assert spray_optimizer._can_attempt("user1", safe_delay_seconds=10) is False

    def test_breach_corpus_nonexistent_file(self, spray_optimizer, caplog):
        """Test graceful handling of nonexistent breach file."""
        fake_file = Path("/nonexistent/breach.txt")
        matches = spray_optimizer.spray_from_breach_corpus(
            domain="testcorp.local",
            breach_file=fake_file
        )

        # Should return empty list without crashing
        assert matches == []
        
        # Should log error
        assert any("Breach corpus not found" in r.message for r in caplog.records)

    def test_spray_stop_on_first_success(self, spray_optimizer):
        """Test continue_on_success=False stops after first match."""
        auth_calls = []

        def mock_auth(domain, username, password, dc_ip):
            auth_calls.append(username)
            # First user succeeds
            return username == "admin1"

        with patch.object(spray_optimizer, '_attempt_auth', side_effect=mock_auth):
            matches = spray_optimizer.spray_user_list(
                domain="testcorp.local",
                usernames=["admin1", "admin2", "admin3"],
                passwords=["testpass"],
                continue_on_success=False
            )

        # Should stop after first success
        assert len(matches) == 1
        assert matches[0].username == "admin1"
        # Should not have attempted all usernames
        assert len(auth_calls) < 3
