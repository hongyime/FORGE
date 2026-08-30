"""Priority scoring and query catalog for automation cycle.

Implements P1 priority scoring formula:
    source_count * 2.0 + owned_source * 3.0 + recurrence_count * 1.5 
    - proof_freshness_days * 0.1 + reachable_services * 0.5

Provides query catalog for target prioritization and suppression signatures
to eliminate noise from known false positives.
"""
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
from pathlib import Path


class PriorityTier(str, Enum):
    """Priority tier classification."""
    CRITICAL = "critical"   # 90+
    HIGH = "high"           # 80-89
    MEDIUM = "medium"       # 70-79
    LOW = "low"             # 60-69
    MINIMAL = "minimal"     # <60


@dataclass
class TargetScore:
    """Calculated priority score for a target."""
    target: str
    score: float
    tier: PriorityTier
    source_count: int
    owned_source: bool
    recurrence_count: int
    proof_freshness_days: int
    reachable_services: int
    components: Dict[str, float] = field(default_factory=dict)
    suppressed: bool = False
    suppression_reason: Optional[str] = None


@dataclass 
class SuppressionSignature:
    """Signature for suppressing known false positives or noise."""
    signature_id: str
    pattern: str  # Regex or exact match pattern
    target_type: str  # domain, ip, url, email, etc.
    reason: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    created_by: str = "automation"
    tags: List[str] = field(default_factory=list)


def calculate_priority_score(
    source_count: int = 0,
    owned_source: bool = False,
    recurrence_count: int = 0,
    proof_freshness_days: int = 365,
    reachable_services: int = 0,
) -> float:
    """Calculate priority score using P1 formula.
    
    Formula:
        source_count * 2.0 + owned_source * 3.0 + recurrence_count * 1.5
        - proof_freshness_days * 0.1 + reachable_services * 0.5
    
    Args:
        source_count: Number of sources confirming this target.
        owned_source: Whether an owned/verified source observed this.
        recurrence_count: Number of times this target recurred.
        proof_freshness_days: Days since last proof/validation.
        reachable_services: Number of reachable services observed.
    
    Returns:
        Priority score (float, range 0-100 typically).
    """
    score = 0.0
    
    # Source confirmation weight
    source_component = source_count * 2.0
    score += source_component
    
    # Owned source high confidence bonus
    owned_component = 3.0 if owned_source else 0.0
    score += owned_component
    
    # Recurrence indicates persistent exposure
    recurrence_component = recurrence_count * 1.5
    score += recurrence_component
    
    # Freshness penalty - older proofs are less actionable
    freshness_penalty = proof_freshness_days * 0.1
    score -= freshness_penalty
    
    # Service density indicates attack surface
    services_component = reachable_services * 0.5
    score += services_component
    
    return max(0.0, score)


def score_to_tier(score: float) -> PriorityTier:
    """Convert numeric score to priority tier.
    
    Args:
        score: Numeric priority score.
    
    Returns:
        PriorityTier classification.
    """
    if score >= 90:
        return PriorityTier.CRITICAL
    elif score >= 80:
        return PriorityTier.HIGH
    elif score >= 70:
        return PriorityTier.MEDIUM
    elif score >= 60:
        return PriorityTier.LOW
    else:
        return PriorityTier.MINIMAL


class QueryCatalog:
    """Catalog of queries for target prioritization."""
    
    def __init__(self):
        self._queries: Dict[str, Dict[str, Any]] = {}
        self._targets: Dict[str, TargetScore] = {}
        self._suppressions: Dict[str, SuppressionSignature] = {}
    
    def register_query(
        self,
        query_id: str,
        query_type: str,
        parameters: Dict[str, Any],
        source_weights: Optional[Dict[str, float]] = None,
    ) -> None:
        """Register a query in the catalog.
        
        Args:
            query_id: Unique query identifier.
            query_type: Type of query (connector, cti, discovery, etc.).
            parameters: Query parameters.
            source_weights: Optional weight multipliers per source.
        """
        self._queries[query_id] = {
            "query_id": query_id,
            "query_type": query_type,
            "parameters": parameters,
            "source_weights": source_weights or {},
            "created_at": datetime.utcnow().isoformat(),
        }
    
    def add_suppression(
        self,
        signature_id: str,
        pattern: str,
        target_type: str,
        reason: str,
        expires_days: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """Add a suppression signature.
        
        Args:
            signature_id: Unique signature identifier.
            pattern: Regex or exact match pattern.
            target_type: Type of target to suppress.
            reason: Reason for suppression.
            expires_days: Optional expiration in days.
            tags: Optional tags for categorization.
        """
        now = datetime.utcnow()
        expires_at = None
        if expires_days:
            expires_at = now + timedelta(days=expires_days)
        
        self._suppressions[signature_id] = SuppressionSignature(
            signature_id=signature_id,
            pattern=pattern,
            target_type=target_type,
            reason=reason,
            created_at=now,
            expires_at=expires_at,
            tags=tags or [],
        )
    
    def is_suppressed(self, target: str, target_type: str) -> tuple[bool, Optional[str]]:
        """Check if a target matches any active suppression.
        
        Args:
            target: Target value to check.
            target_type: Type of target.
        
        Returns:
            Tuple of (is_suppressed, reason).
        """
        import re
        now = datetime.utcnow()
        
        for sig_id, sig in self._suppressions.items():
            # Skip expired suppressions
            if sig.expires_at and sig.expires_at < now:
                continue
            
            # Skip type mismatch
            if sig.target_type != target_type and sig.target_type != "*":
                continue
            
            # Check pattern match
            try:
                if re.search(sig.pattern, target, re.IGNORECASE):
                    return True, sig.reason
            except re.error:
                # Invalid regex, try exact match
                if sig.pattern.lower() in target.lower():
                    return True, sig.reason
        
        return False, None
    
    def score_target(
        self,
        target: str,
        source_count: int = 0,
        owned_source: bool = False,
        recurrence_count: int = 0,
        proof_freshness_days: int = 365,
        reachable_services: int = 0,
    ) -> TargetScore:
        """Score a target using P1 formula.
        
        Args:
            target: Target identifier.
            source_count: Number of sources.
            owned_source: Whether owned source observed.
            recurrence_count: Recurrence count.
            proof_freshness_days: Days since proof.
            reachable_services: Service count.
        
        Returns:
            TargetScore with calculated priority.
        """
        # Check suppression
        # Assume domain type for now, could be enhanced
        suppressed, reason = self.is_suppressed(target, "domain")
        
        score = calculate_priority_score(
            source_count=source_count,
            owned_source=owned_source,
            recurrence_count=recurrence_count,
            proof_freshness_days=proof_freshness_days,
            reachable_services=reachable_services,
        )
        
        tier = score_to_tier(score)
        
        components = {
            "source_count": source_count * 2.0,
            "owned_source": 3.0 if owned_source else 0.0,
            "recurrence_count": recurrence_count * 1.5,
            "freshness_penalty": proof_freshness_days * 0.1,
            "reachable_services": reachable_services * 0.5,
        }
        
        target_score = TargetScore(
            target=target,
            score=score,
            tier=tier,
            source_count=source_count,
            owned_source=owned_source,
            recurrence_count=recurrence_count,
            proof_freshness_days=proof_freshness_days,
            reachable_services=reachable_services,
            components=components,
            suppressed=suppressed,
            suppression_reason=reason,
        )
        
        self._targets[target] = target_score
        return target_score
    
    def get_top_priorities(self, limit: int = 100) -> List[TargetScore]:
        """Get top priority targets sorted by score.
        
        Args:
            limit: Maximum targets to return.
        
        Returns:
            List of TargetScore sorted by priority.
        """
        # Filter out suppressed targets
        active = [t for t in self._targets.values() if not t.suppressed]
        
        # Sort by score descending
        sorted_targets = sorted(active, key=lambda t: t.score, reverse=True)
        
        return sorted_targets[:limit]
    
    def export_catalog(self) -> Dict[str, Any]:
        """Export catalog state as JSON-serializable dict.
        
        Returns:
            Dict with queries, targets, and suppressions.
        """
        return {
            "schema_version": "forge.automation.query_catalog.v1",
            "queries": dict(self._queries),
            "targets": {
                t: {
                    "score": ts.score,
                    "tier": ts.tier.value,
                    "source_count": ts.source_count,
                    "owned_source": ts.owned_source,
                    "recurrence_count": ts.recurrence_count,
                    "proof_freshness_days": ts.proof_freshness_days,
                    "reachable_services": ts.reachable_services,
                    "suppressed": ts.suppressed,
                }
                for t, ts in self._targets.items()
            },
            "suppressions": {
                s: {
                    "signature_id": sig.signature_id,
                    "pattern": sig.pattern,
                    "target_type": sig.target_type,
                    "reason": sig.reason,
                    "created_at": sig.created_at.isoformat(),
                    "expires_at": sig.expires_at.isoformat() if sig.expires_at else None,
                    "tags": sig.tags,
                }
                for s, sig in self._suppressions.items()
            },
        }


# Default suppression signatures for common noise
DEFAULT_SUPPRESSIONS = [
    SuppressionSignature(
        signature_id="suppress_localhost",
        pattern=r"^localhost$|^127\.0\.0\.1$|^::1$",
        target_type="*",
        reason="Local loopback address",
        created_at=datetime.utcnow(),
        tags=["infrastructure", "local"],
    ),
    SuppressionSignature(
        signature_id="suppress_private_ipv4",
        pattern=r"^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        target_type="ip",
        reason="Private IPv4 range",
        created_at=datetime.utcnow(),
        tags=["infrastructure", "private"],
    ),
    SuppressionSignature(
        signature_id="suppress_example_domains",
        pattern=r"\.example\.com$|\.example\.org$|\.test$|\.local$",
        target_type="domain",
        reason="Example/test domain",
        created_at=datetime.utcnow(),
        tags=["documentation", "test"],
    ),
]


def create_catalog_with_defaults() -> QueryCatalog:
    """Create a QueryCatalog with default suppressions loaded.
    
    Returns:
        QueryCatalog instance with common noise suppressed.
    """
    catalog = QueryCatalog()
    
    for sig in DEFAULT_SUPPRESSIONS:
        catalog._suppressions[sig.signature_id] = sig
    
    return catalog
