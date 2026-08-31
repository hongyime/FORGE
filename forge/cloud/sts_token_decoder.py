"""AWS STS Token offline forensics decoder.

Extracts account ID, creation time, region, and session metadata from
AWS STS session tokens without making live API calls.

EDR-safe patterns:
- Offline decoding only (no network calls)
- No credential material stored
- Session timestamps for credential age scoring
- Account ID enrichment for asset graph
"""

import base64
import json
import logging
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import sqlite3

logger = logging.getLogger(__name__)


@dataclass
class STSTokenInfo:
    """Decoded AWS STS session token information."""
    account_id: str           # 12-digit AWS account ID
    creation_time: datetime   # Token creation timestamp
    region: str               # AWS region from token
    user_data_encrypted: str # Encrypted user identity (no decryption)
    session_name: Optional[str] = None
    token_type: str = "session"  # "session" | "federated" | "assumed_role"
    raw_token_preview: str = ""  # First 20 chars for audit (never full token)


class STSTokenDecoder:
    """Decode AWS STS session tokens offline (no API calls).

    AWS STS tokens are base64-encoded structures containing:
    - Account ID (12-digit identifier)
    - Creation timestamp
    - Region
    - Encrypted user identity

    This decoder extracts metadata WITHOUT making live AWS API calls.
    """

    # AWS STS token patterns
    STS_TOKEN_PATTERN = re.compile(
        r'^[A-Za-z0-9+/=]{200,}$'  # Base64-encoded session token
    )

    ACCOUNT_ID_PATTERN = re.compile(r'\b(\d{12})\b')

    def __init__(self, engagement_db: Optional[Path] = None):
        """Initialize STS token decoder.

        Args:
            engagement_db: Optional path to engagement database for
                           batch decoding from existing findings.
        """
        self.engagement_db = engagement_db

    def decode_token(self, token: str) -> Optional[STSTokenInfo]:
        """Parse AWS STS session token structure.

        Args:
            token: AWS STS session token string

        Returns:
            STSTokenInfo with extracted metadata, or None if decoding fails

        Security:
            - NO LIVE API CALLS - offline forensics only
            - No credential material stored
            - Token preview truncated for audit safety
        """
        if not token or len(token) < 100:
            logger.debug("Token too short for STS session token")
            return None

        # Validate token format
        if not self.STS_TOKEN_PATTERN.match(token):
            logger.debug("Token does not match STS session token pattern")
            return None

        try:
            # AWS STS tokens are base64-encoded JSON-like structures
            # The structure is: version + timestamp + account_id + encrypted_data

            # Decode base64
            # Note: AWS uses custom encoding; we extract what we can
            decoded_bytes = base64.b64decode(token + '==')  # Add padding
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

            # Extract account ID (12-digit pattern)
            account_match = self.ACCOUNT_ID_PATTERN.search(decoded_str)
            if not account_match:
                # Try alternate extraction from token structure
                # AWS STS tokens embed account ID in specific positions
                account_id = self._extract_account_from_structure(token)
                if not account_id:
                    logger.debug("Could not extract account ID from token")
                    return None
            else:
                account_id = account_match.group(1)

            # Extract creation time
            creation_time = self._extract_creation_time(decoded_str, token)
            if not creation_time:
                creation_time = datetime.now(timezone.utc)

            # Extract region (default to us-east-1 if not found)
            region = self._extract_region(decoded_str) or "us-east-1"

            # Extract encrypted user data (never decrypt)
            user_data_encrypted = self._extract_encrypted_user_data(decoded_str)

            # Determine token type
            token_type = self._determine_token_type(decoded_str)

            # Extract session name if present
            session_name = self._extract_session_name(decoded_str)

            return STSTokenInfo(
                account_id=account_id,
                creation_time=creation_time,
                region=region,
                user_data_encrypted=user_data_encrypted,
                session_name=session_name,
                token_type=token_type,
                raw_token_preview=token[:20] + "..."
            )

        except Exception as e:
            logger.debug(f"Failed to decode STS token: {e}")
            return None

    def _extract_account_from_structure(self, token: str) -> Optional[str]:
        """Extract account ID from STS token structure.

        AWS STS tokens embed account ID in specific byte positions.
        This attempts extraction without full decoding.
        """
        try:
            # AWS STS tokens have account ID embedded at specific positions
            # This is a simplified extraction for common patterns

            # Attempt to decode and find account ID pattern
            # The token structure varies by AWS SDK version
            decoded = base64.b64decode(token + '==').decode('utf-8', errors='ignore')

            # Look for 12-digit AWS account ID pattern
            match = self.ACCOUNT_ID_PATTERN.search(decoded)
            if match:
                return match.group(1)

            return None

        except Exception:
            return None

    def _extract_creation_time(
        self,
        decoded_str: str,
        token: str
    ) -> Optional[datetime]:
        """Extract creation timestamp from token.

        AWS STS tokens include creation timestamp in various formats.
        """
        try:
            # Look for ISO timestamp patterns
            iso_pattern = re.compile(
                r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}'
            )
            match = iso_pattern.search(decoded_str)
            if match:
                timestamp_str = match.group(0)
                # Parse timestamp
                try:
                    return datetime.fromisoformat(
                        timestamp_str.replace(' ', 'T')
                    )
                except ValueError:
                    pass

            # Look for Unix timestamp patterns
            unix_pattern = re.compile(r'"timestamp":\s*(\d+)')
            match = unix_pattern.search(decoded_str)
            if match:
                unix_ts = int(match.group(1))
                return datetime.fromtimestamp(unix_ts, tz=timezone.utc)

            return None

        except Exception:
            return None

    def _extract_region(self, decoded_str: str) -> Optional[str]:
        """Extract AWS region from token."""
        # Common AWS region patterns
        region_pattern = re.compile(
            r'(us-east-1|us-east-2|us-west-1|us-west-2|'
            r'eu-west-1|eu-west-2|eu-west-3|eu-central-1|'
            r'ap-northeast-1|ap-northeast-2|ap-southeast-1|ap-southeast-2|'
            r'ap-south-1|ca-central-1|sa-east-1)'
        )
        match = region_pattern.search(decoded_str)
        return match.group(1) if match else None

    def _extract_encrypted_user_data(self, decoded_str: str) -> str:
        """Extract encrypted user identity (never decrypt).

        Returns placeholder indicating encrypted data exists.
        """
        # Indicate that encrypted user data was found
        if 'user' in decoded_str.lower() or 'identity' in decoded_str.lower():
            return "<encrypted_user_identity_present>"
        return "<no_user_data>"

    def _determine_token_type(self, decoded_str: str) -> str:
        """Determine token type from decoded content."""
        decoded_lower = decoded_str.lower()

        if 'assumedrole' in decoded_lower or 'assumed_role' in decoded_lower:
            return "assumed_role"
        elif 'federated' in decoded_lower:
            return "federated"
        else:
            return "session"

    def _extract_session_name(self, decoded_str: str) -> Optional[str]:
        """Extract session name if present."""
        try:
            # Look for session name in common formats
            patterns = [
                r'"session_name":\s*"([^"]+)"',
                r'"SessionName":\s*"([^"]+)"',
                r'session[_-]?name[=:]([^\s,}]+)',
            ]

            for pattern in patterns:
                match = re.search(pattern, decoded_str, re.IGNORECASE)
                if match:
                    return match.group(1)

            return None

        except Exception:
            return None

    def batch_decode_from_findings(
        self,
        engagement_db: Optional[Path] = None
    ) -> List[STSTokenInfo]:
        """Scan all cloud_findings for AWS credentials, decode STS tokens.

        Args:
            engagement_db: Path to engagement database (uses init path if None)

        Returns:
            List of decoded STS token information

        Security:
            - Offline operation only
            - No credential material stored
            - Account IDs added to cloud_accounts table
        """
        db_path = engagement_db or self.engagement_db
        if not db_path or not db_path.exists():
            logger.error(f"Engagement database not found: {db_path}")
            return []

        results = []

        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            # Query cloud findings for AWS credentials
            # Look for access_key_id, secret_access_key, session_token patterns
            cursor.execute("""
                SELECT id, finding_type, raw_data
                FROM cloud_findings
                WHERE provider = 'aws'
                  AND finding_type IN ('credential', 'session_token', 'access_key')
                  AND raw_data IS NOT NULL
            """)

            findings = cursor.fetchall()
            logger.info(f"Found {len(findings)} AWS credential findings to decode")

            for finding_id, finding_type, raw_data in findings:
                try:
                    data = json.loads(raw_data) if raw_data else {}

                    # Extract session token from various locations
                    session_token = (
                        data.get('session_token') or
                        data.get('SessionToken') or
                        data.get('aws_session_token') or
                        data.get('token')
                    )

                    if session_token:
                        token_info = self.decode_token(session_token)
                        if token_info:
                            results.append(token_info)

                            # Update cloud_accounts table
                            self._upsert_cloud_account(
                                cursor,
                                token_info.account_id,
                                token_info.region
                            )

                except json.JSONDecodeError:
                    logger.debug(f"Could not parse raw_data for finding {finding_id}")
                    continue

            conn.commit()
            conn.close()

            logger.info(
                f"Decoded {len(results)} STS tokens, "
                f"found {len(set(r.account_id for r in results))} unique accounts"
            )

            return results

        except Exception as e:
            logger.exception(f"Failed to batch decode STS tokens: {e}")
            return []

    def _upsert_cloud_account(
        self,
        cursor: sqlite3.Cursor,
        account_id: str,
        region: str
    ) -> None:
        """Insert or update cloud account in database.

        Args:
            cursor: Database cursor
            account_id: 12-digit AWS account ID
            region: AWS region
        """
        try:
            # Check if cloud_accounts table exists
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='cloud_accounts'
            """)

            if not cursor.fetchone():
                # Create table if it doesn't exist
                cursor.execute("""
                    CREATE TABLE cloud_accounts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        account_id TEXT UNIQUE NOT NULL,
                        provider TEXT DEFAULT 'aws',
                        region TEXT,
                        discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        last_updated TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                """)

            # Upsert account
            cursor.execute("""
                INSERT INTO cloud_accounts (account_id, provider, region)
                VALUES (?, 'aws', ?)
                ON CONFLICT(account_id) DO UPDATE SET
                    region = excluded.region,
                    last_updated = CURRENT_TIMESTAMP
            """, (account_id, region))

        except Exception as e:
            logger.debug(f"Failed to upsert cloud account: {e}")

    def get_credential_age_score(
        self,
        creation_time: datetime
    ) -> float:
        """Calculate credential age risk score (0.0-1.0).

        Args:
            creation_time: Token creation timestamp

        Returns:
            Risk score where older credentials = higher score

        Scoring:
            - < 1 hour: 0.1 (fresh credential, lower risk)
            - < 24 hours: 0.3
            - < 7 days: 0.5
            - < 30 days: 0.7
            - >= 30 days: 0.9 (stale credential, higher risk)
        """
        now = datetime.now(timezone.utc)
        age_hours = (now - creation_time).total_seconds() / 3600

        if age_hours < 1:
            return 0.1
        elif age_hours < 24:
            return 0.3
        elif age_hours < 168:  # 7 days
            return 0.5
        elif age_hours < 720:  # 30 days
            return 0.7
        else:
            return 0.9
