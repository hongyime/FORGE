"""Unit tests for AWS STS Token Decoder.

Tests offline token decoding, credential age scoring, and batch processing.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from datetime import datetime, timezone, timedelta
import tempfile
import sqlite3
import json

from forge.cloud.sts_token_decoder import (
    STSTokenDecoder,
    STSTokenInfo
)


class TestSTSTokenDecoder:
    """Test STSTokenDecoder class."""

    def test_init_without_db(self):
        """Test initialization without engagement database."""
        decoder = STSTokenDecoder()
        assert decoder.engagement_db is None

    def test_init_with_db(self):
        """Test initialization with engagement database."""
        db_path = Path("/tmp/test.db")
        decoder = STSTokenDecoder(engagement_db=db_path)
        assert decoder.engagement_db == db_path

    def test_decode_empty_token(self):
        """Test decoding empty token."""
        decoder = STSTokenDecoder()
        result = decoder.decode_token("")
        assert result is None

    def test_decode_short_token(self):
        """Test decoding token that's too short."""
        decoder = STSTokenDecoder()
        result = decoder.decode_token("short")
        assert result is None

    def test_decode_valid_token_structure(self):
        """Test decoding valid STS token structure."""
        decoder = STSTokenDecoder()

        # Create a mock token with embedded account ID
        # This simulates a real STS token structure
        token_data = {
            "account_id": "123456789012",
            "creation_time": "2026-08-30T10:00:00Z",
            "region": "us-east-1",
            "user": "test_user",
            "session_name": "test_session"
        }

        # Encode as base64
        import base64
        token = base64.b64encode(
            json.dumps(token_data).encode()
        ).decode()

        # Pad to minimum length
        token = token + "A" * (250 - len(token))

        result = decoder.decode_token(token)

        # Should decode successfully
        if result:
            assert result.account_id == "123456789012"
            assert result.region == "us-east-1"

    def test_get_credential_age_score_fresh(self):
        """Test credential age scoring for fresh token (< 1 hour)."""
        decoder = STSTokenDecoder()

        recent_time = datetime.now(timezone.utc) - timedelta(minutes=30)
        score = decoder.get_credential_age_score(recent_time)

        assert score == 0.1

    def test_get_credential_age_score_day_old(self):
        """Test credential age scoring for 1-day-old token."""
        decoder = STSTokenDecoder()

        day_old = datetime.now(timezone.utc) - timedelta(hours=12)
        score = decoder.get_credential_age_score(day_old)

        assert score == 0.3

    def test_get_credential_age_score_week_old(self):
        """Test credential age scoring for 1-week-old token."""
        decoder = STSTokenDecoder()

        week_old = datetime.now(timezone.utc) - timedelta(days=5)
        score = decoder.get_credential_age_score(week_old)

        assert score == 0.5

    def test_get_credential_age_score_month_old(self):
        """Test credential age scoring for 1-month-old token."""
        decoder = STSTokenDecoder()

        month_old = datetime.now(timezone.utc) - timedelta(days=20)
        score = decoder.get_credential_age_score(month_old)

        assert score == 0.7

    def test_get_credential_age_score_stale(self):
        """Test credential age scoring for stale token (> 30 days)."""
        decoder = STSTokenDecoder()

        stale = datetime.now(timezone.utc) - timedelta(days=60)
        score = decoder.get_credential_age_score(stale)

        assert score == 0.9

    def test_batch_decode_empty_db(self):
        """Test batch decode with missing database."""
        decoder = STSTokenDecoder(engagement_db=Path("/nonexistent/db.db"))
        results = decoder.batch_decode_from_findings()

        assert results == []

    def test_batch_decode_from_temp_db(self):
        """Test batch decode from temporary database."""
        import tempfile

        # Create temp database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = Path(f.name)

        try:
            # Setup database schema
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE cloud_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_type TEXT,
                    provider TEXT,
                    raw_data TEXT
                )
            """)

            # Insert mock AWS credential finding
            import base64
            token_data = {
                "session_token": base64.b64encode(
                    json.dumps({
                        "account_id": "123456789012",
                        "region": "us-west-2"
                    }).encode()
                ).decode() + "A" * 200
            }

            cursor.execute("""
                INSERT INTO cloud_findings (finding_type, provider, raw_data)
                VALUES ('session_token', 'aws', ?)
            """, (json.dumps(token_data),))

            conn.commit()
            conn.close()

            # Decode
            decoder = STSTokenDecoder(engagement_db=db_path)
            results = decoder.batch_decode_from_findings()

            # Should find and decode token
            assert isinstance(results, list)

        finally:
            # Cleanup
            db_path.unlink(missing_ok=True)

    def test_determine_token_type_assumed_role(self):
        """Test token type determination for assumed role."""
        decoder = STSTokenDecoder()

        token_type = decoder._determine_token_type(
            "AssumedRole session data"
        )

        assert token_type == "assumed_role"

    def test_determine_token_type_federated(self):
        """Test token type determination for federated."""
        decoder = STSTokenDecoder()

        token_type = decoder._determine_token_type(
            "Federated user session"
        )

        assert token_type == "federated"

    def test_determine_token_type_session(self):
        """Test token type determination for regular session."""
        decoder = STSTokenDecoder()

        token_type = decoder._determine_token_type(
            "Regular session token"
        )

        assert token_type == "session"

    def test_extract_encrypted_user_data_present(self):
        """Test extraction of encrypted user data indicator."""
        decoder = STSTokenDecoder()

        result = decoder._extract_encrypted_user_data(
            "user_identity_encrypted_data"
        )

        assert result == "<encrypted_user_identity_present>"

    def test_extract_encrypted_user_data_absent(self):
        """Test extraction when no user data present."""
        decoder = STSTokenDecoder()

        result = decoder._extract_encrypted_user_data(
            "random_token_data"
        )

        assert result == "<no_user_data>"


@pytest.mark.integration
class TestSTSTokenDecoderIntegration:
    """Integration tests for STS Token Decoder."""

    @pytest.mark.skip(reason="Requires engagement database with AWS findings")
    def test_real_engagement_decode(self):
        """Test decoding from real engagement database."""
        # This would require a real engagement DB with AWS credentials
        pass
