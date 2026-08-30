"""Secret auto-feeding into Forge target loop.

When secrets are discovered (Gitleaks/TruffleHog/keyscan), extract
target seeds and feed them back into the target feed for autonomous
scanning.

Implements plan P1: secrets/configs as forge inputs in loop.
"""
import re
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse


@dataclass
class SecretTargetExtraction:
    """Result of extracting targets from a secret."""
    secret_type: str
    secret_id: str  # Redacted hash
    extracted_targets: List[str]
    target_types: List[str]  # domain, email, cloud_ref, etc.
    confidence: float
    domain: Optional[str] = None
    organization: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


def extract_targets_from_aws_key(
    access_key: str,
    secret_key_redacted: str,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
) -> SecretTargetExtraction:
    """Extract targets from AWS credentials.
    
    Args:
        access_key: AWS access key ID (e.g., AKIAIOSFODNN7EXAMPLE)
        secret_key_redacted: Redacted secret key
        account_id: Optional extracted account ID
        region: Optional default region
    
    Returns:
        SecretTargetExtraction with cloud_ref targets
    """
    targets = []
    target_types = []
    
    # Cloud ref for account
    if account_id:
        targets.append(f"cloud_ref:aws:{account_id}")
        target_types.append("cloud_ref")
    
    # Region-based endpoints
    if region:
        targets.append(f"cloud_ref:aws:{region}")
        target_types.append("cloud_ref")
    
    # Extract account ID from access key prefix (AKIA)
    if access_key.startswith("AKIA"):
        # AWS access key format: AKIA + 16 chars
        # Could query STS caller identity for more metadata
        pass
    
    return SecretTargetExtraction(
        secret_type="aws_access_key",
        secret_id=f"aws:{access_key[:8]}...",
        extracted_targets=targets,
        target_types=target_types,
        confidence=0.8 if account_id else 0.5,
        metadata={"account_id": account_id, "region": region},
    )


def extract_targets_from_database_url(
    db_url: str,
    db_type: Optional[str] = None,
) -> SecretTargetExtraction:
    """Extract targets from database connection string.
    
    Args:
        db_url: Database connection URL
        db_type: Optional database type (postgres, mysql, mongodb, etc.)
    
    Returns:
        SecretTargetExtraction with hostname/email targets
    """
    targets = []
    target_types = []
    
    try:
        parsed = urlparse(db_url)
        
        # Hostname
        if parsed.hostname:
            targets.append(parsed.hostname)
            target_types.append("domain")
        
        # Port-based service detection
        if parsed.port:
            port_services = {
                5432: "postgres",
                3306: "mysql",
                27017: "mongodb",
                6379: "redis",
                9200: "elasticsearch",
                9042: "cassandra",
            }
            service = port_services.get(parsed.port, "database")
            targets.append(f"service:{parsed.hostname}:{parsed.port}")
            target_types.append("service")
        
        # Extract username if present
        if parsed.username:
            if '@' in parsed.username:
                # Username is an email
                targets.append(parsed.username)
                target_types.append("email")
        
        # Extract database name from path
        if parsed.path and len(parsed.path) > 1:
            db_name = parsed.path.strip('/')
            # Could be used as metadata
            pass
            
    except Exception:
        pass
    
    return SecretTargetExtraction(
        secret_type=db_type or "database_url",
        secret_id=f"db:{db_url[:20]}...",
        extracted_targets=targets,
        target_types=target_types,
        confidence=0.9,
        domain=parsed.hostname if parsed else None,
    )


def extract_targets_from_github_token(
    token_redacted: str,
    token_type: str = "pat",
) -> SecretTargetExtraction:
    """Extract targets from GitHub token.
    
    Args:
        token_redacted: Redacted GitHub token
        token_type: Token type (pat, oauth, etc.)
    
    Returns:
        SecretTargetExtraction with GitHub organization targets
    """
    targets = []
    target_types = []
    
    # GitHub tokens could be used to discover organizations
    # For now, just flag as authenticated GitHub source
    targets.append("github.com")
    target_types.append("domain")
    
    return SecretTargetExtraction(
        secret_type=f"github_{token_type}",
        secret_id=f"github:{token_redacted[:10]}...",
        extracted_targets=targets,
        target_types=target_types,
        confidence=0.7,
        organization="github",
    )


def extract_targets_from_email(
    email: str,
) -> SecretTargetExtraction:
    """Extract targets from email address.
    
    Args:
        email: Email address
    
    Returns:
        SecretTargetExtraction with email/domain targets
    """
    targets = [email]
    target_types = ["email"]
    
    # Extract domain
    if '@' in email:
        domain = email.split('@')[-1]
        targets.append(domain)
        target_types.append("domain")
    
    return SecretTargetExtraction(
        secret_type="email",
        secret_id=f"email:{email}",
        extracted_targets=targets,
        target_types=target_types,
        confidence=0.95,
        domain=email.split('@')[-1] if '@' in email else None,
        organization=domain if '@' in email else None,
    )


def extract_targets_from_stripe_key(
    api_key: str,
) -> SecretTargetExtraction:
    """Extract targets from Stripe API key.
    
    Args:
        api_key: Stripe API key (sk_*, pk_*)
    
    Returns:
        SecretTargetExtraction with Stripe account targets
    """
    targets = []
    target_types = []
    
    # Stripe keys: sk_live_..., sk_test_..., pk_live_..., pk_test_...
    if api_key.startswith("sk_live") or api_key.startswith("pk_live"):
        targets.append("stripe.com")
        target_types.append("domain")
    
    return SecretTargetExtraction(
        secret_type="stripe_api_key",
        secret_id=f"stripe:{api_key[:10]}...",
        extracted_targets=targets,
        target_types=target_types,
        confidence=0.8,
        organization="stripe",
    )


def extract_targets_from_slack_token(
    token: str,
) -> SecretTargetExtraction:
    """Extract targets from Slack token.
    
    Args:
        token: Slack token (xoxb-*, xoxp-*, etc.)
    
    Returns:
        SecretTargetExtraction with Slack workspace targets
    """
    targets = []
    target_types = []
    
    # Slack tokens: xoxb-*, xoxp-*, xoxs-*
    if token.startswith("xox"):
        targets.append("slack.com")
        target_types.append("domain")
    
    return SecretTargetExtraction(
        secret_type="slack_token",
        secret_id=f"slack:{token[:10]}...",
        extracted_targets=targets,
        target_types=target_types,
        confidence=0.8,
        organization="slack",
    )


def extract_targets_generic(
    secret_value: str,
    secret_type: str,
) -> SecretTargetExtraction:
    """Generic target extraction from any secret.
    
    Args:
        secret_value: Secret value to scan
        secret_type: Type of secret
    
    Returns:
        SecretTargetExtraction with extracted targets
    """
    targets = []
    target_types = []
    
    # Email pattern
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, secret_value)
    targets.extend(emails)
    target_types.extend(["email"] * len(emails))
    
    # URL pattern
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, secret_value)
    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                targets.append(parsed.hostname)
                target_types.append("domain")
        except Exception:
            pass
    
    # IP pattern
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, secret_value)
    targets.extend(ips)
    target_types.extend(["ip"] * len(ips))
    
    # Domain pattern (heuristic)
    domain_pattern = r'\b[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+\b'
    domains = re.findall(domain_pattern, secret_value)
    for domain_match in domains:
        domain = ''.join(domain_match)
        if len(domain) > 3 and '.' in domain:
            targets.append(domain)
            target_types.append("domain")
    
    # Deduplicate
    seen = set()
    unique_targets = []
    unique_types = []
    for target, target_type in zip(targets, target_types):
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)
            unique_types.append(target_type)
    
    return SecretTargetExtraction(
        secret_type=secret_type,
        secret_id=f"{secret_type}:{hash(secret_value) % 10000:04d}",
        extracted_targets=unique_targets,
        target_types=unique_types,
        confidence=0.5,  # Generic extraction is lower confidence
    )


def auto_feed_secrets_to_target_feed(
    secret_observations: List[Dict[str, Any]],
    existing_targets: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Auto-feed discovered secrets into target feed.
    
    This is the main entry point for secrets auto-feeding loop.
    
    Args:
        secret_observations: List of secret observations from keyscan
        existing_targets: Optional set of existing targets to dedupe
    
    Returns:
        List of new target candidates for feed
    """
    if existing_targets is None:
        existing_targets = set()
    
    new_targets = []
    
    for obs in secret_observations:
        secret_type = obs.get("secret_type", "unknown")
        secret_value = obs.get("secret_value_redacted", "")
        
        # Extract based on type
        if secret_type.startswith("aws_"):
            extraction = extract_targets_from_aws_key(
                access_key=obs.get("access_key", ""),
                secret_key_redacted=secret_value,
                account_id=obs.get("account_id"),
                region=obs.get("region"),
            )
        elif secret_type == "database_url":
            extraction = extract_targets_from_database_url(
                db_url=obs.get("url_redacted", secret_value),
                db_type=obs.get("db_type"),
            )
        elif secret_type == "github_token":
            extraction = extract_targets_from_github_token(
                token_redacted=secret_value,
                token_type=obs.get("token_type", "pat"),
            )
        elif secret_type == "email":
            extraction = extract_targets_from_email(
                email=obs.get("email", secret_value),
            )
        elif secret_type == "stripe_api_key":
            extraction = extract_targets_from_stripe_key(
                api_key=secret_value,
            )
        elif secret_type == "slack_token":
            extraction = extract_targets_from_slack_token(
                token=secret_value,
            )
        else:
            extraction = extract_targets_generic(
                secret_value=secret_value,
                secret_type=secret_type,
            )
        
        # Add new targets to feed
        for target, target_type in zip(
            extraction.extracted_targets,
            extraction.target_types
        ):
            if target not in existing_targets:
                new_targets.append({
                    "target": target,
                    "target_type": target_type,
                    "source": f"secret:{secret_type}",
                    "confidence": extraction.confidence,
                    "provenance": {
                        "secret_type": secret_type,
                        "secret_id": extraction.secret_id,
                        "extracted_at": datetime.utcnow().isoformat(),
                    },
                })
                existing_targets.add(target)
    
    return new_targets
