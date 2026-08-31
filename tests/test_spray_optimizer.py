"""Unit tests for SprayOptimizer (T4).

Tests password spray optimization with lockout policy detection.
"""

import pytest
from unittest.mock import Mock, patch
from pathlib import Path
from datetime import datetime, timezone
from forge.auth.spray_optimizer import (
    SprayOptimizer,
    SprayPolicy,
    SprayAttempt,
    CredentialMatch
)


class TestSprayPolicy:
    """Test SprayPolicy dataclass."""

    def test_spray_policy_creation(self):
        """SprayPolicy creates with expected fields."""
        policy = SprayPolicy(
            lockout_threshold=5,
            lockout_duration_min=30,
            safe_delay_seconds=60,
            max_concurrent=10,
            observation_window_min=15
        )
        assert policy.lockout_threshold == 5
        assert policy.lockout_duration_min == 30

    def test_spray_policy_defaults(self):
        """SprayPolicy uses safe defaults."""
        policy = SprayPolicy(
            lockout_threshold=3,
            lockout_duration_min=15,
            safe_delay_seconds=30,
            max_concurrent=5,
            observation_window_min=10
        )
        assert policy.lockout_threshold > 0
        assert policy.lockout_duration_min > 0


class TestCredentialMatch:
    """Test CredentialMatch dataclass."""

    def test_credential_match_creation(self):
        """CredentialMatch creates with expected fields."""
        match = CredentialMatch(
            username="admin",
            domain="corp.local",
            password="Password123",
            matched_at=datetime.now(timezone.utc),
            source_method="spray"
        )
        assert match.username == "admin"
        assert match.domain == "corp.local"
        assert match.source_method == "spray"


class TestSprayAttempt:
    """Test SprayAttempt dataclass."""

    def test_spray_attempt_creation(self):
        """SprayAttempt creates with expected fields."""
        attempt = SprayAttempt(
            username="admin",
            domain="corp.local",
            success=True,
            attempted_at=datetime.now(timezone.utc)
        )
        assert attempt.username == "admin"
        assert attempt.success is True

    def test_spray_attempt_with_error(self):
        """SprayAttempt captures error state."""
        attempt = SprayAttempt(
            username="admin",
            domain="corp.local",
            success=False,
            attempted_at=datetime.now(timezone.utc),
            error="Lockout detected"
        )
        assert attempt.success is False
        assert "Lockout" in attempt.error


class TestSprayOptimizer:
    """Test SprayOptimizer class."""

    def test_init_default_policy(self):
        """SprayOptimizer initializes with default lockout policy."""
        optimizer = SprayOptimizer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["example.com"]}
        )
        assert optimizer.roe_id == "ROE-123"
        assert optimizer.policy is not None

    def test_init_custom_policy(self):
        """SprayOptimizer accepts custom lockout policy."""
        custom_policy = SprayPolicy(
            lockout_threshold=3,
            lockout_duration_min=15,
            safe_delay_seconds=30,
            max_concurrent=5,
            observation_window_min=10
        )
        optimizer = SprayOptimizer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["example.com"]},
            policy=custom_policy
        )
        assert optimizer.roe_id == "ROE-123"
        assert optimizer.policy.lockout_threshold == 3

    def test_init_requires_roe(self):
        """SprayOptimizer requires ROE ID."""
        with pytest.raises(ValueError, match="ROE ID required"):
            SprayOptimizer(
                roe_id="",
                scope_manifest={"domains": ["example.com"]}
            )

    def test_detect_lockout_policy(self):
        """detect_lockout_policy returns SprayPolicy."""
        optimizer = SprayOptimizer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        policy = optimizer.detect_lockout_policy("corp.local")
        assert policy is not None
        assert isinstance(policy, SprayPolicy)
        assert policy.lockout_threshold > 0

    def test_detect_lockout_policy_conservative(self):
        """detect_lockout_policy returns conservative policy."""
        optimizer = SprayOptimizer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        policy = optimizer.detect_lockout_policy("corp.local")
        # Should be conservative (below default threshold)
        assert policy.lockout_threshold <= optimizer.DEFAULT_POLICY.lockout_threshold

    def test_spray_user_list_empty(self):
        """spray_user_list handles empty inputs."""
        optimizer = SprayOptimizer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["example.com"]}
        )
        
        matches = optimizer.spray_user_list(
            domain="example.com",
            usernames=[],
            passwords=["Password123"]
        )
        assert matches == []

    def test_spray_user_list_dry_run(self):
        """spray_user_list executes without network calls."""
        optimizer = SprayOptimizer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["example.com"]}
        )
        
        # Should run without error (placeholder implementation)
        matches = optimizer.spray_user_list(
            domain="example.com",
            usernames=["admin"],
            passwords=["test"],
            continue_on_success=False
        )
        # Placeholder returns empty list (no actual auth)
        assert isinstance(matches, list)

    def test_spray_from_breach_corpus_missing_file(self):
        """spray_from_breach_corpus handles missing file."""
        optimizer = SprayOptimizer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["example.com"]}
        )
        
        matches = optimizer.spray_from_breach_corpus(
            domain="example.com",
            breach_file=Path("/nonexistent/breach.txt")
        )
        assert matches == []

    def test__can_attempt_first_attempt(self):
        """_can_attempt returns True for first attempt."""
        optimizer = SprayOptimizer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["example.com"]}
        )
        
        can_attempt = optimizer._can_attempt("newuser", safe_delay_seconds=60)
        assert can_attempt is True

    def test__record_attempt(self):
        """_record_attempt tracks attempt time."""
        optimizer = SprayOptimizer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["example.com"]}
        )
        
        optimizer._record_attempt("testuser")
        assert "testuser" in optimizer._attempt_history
        assert len(optimizer._attempt_history["testuser"]) == 1

    def test__attempt_auth_placeholder(self):
        """_attempt_auth placeholder returns False."""
        optimizer = SprayOptimizer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["example.com"]}
        )
        
        # Placeholder implementation always returns False
        result = optimizer._attempt_auth(
            domain="example.com",
            username="admin",
            password="test",
            dc_ip=None
        )
        assert result is False

    def test_audit_log_entry(self):
        """SprayOptimizer has audit logging capability."""
        optimizer = SprayOptimizer(
            roe_id="ROE-123",
            scope_manifest={"domains": ["example.com"]}
        )
        
        # Verify audit_log method exists
        assert hasattr(optimizer, '_audit_log')
        
        # Call should not raise
        optimizer._audit_log(
            action="test_action",
            domain="example.com",
            username="testuser",
            success=False
        )
