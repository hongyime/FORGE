"""FORGE Authentication Package.

Password spraying, credential validation, and auth testing.

Security: All auth operations require explicit ROE + scope manifest.
"""

from .spray_optimizer import (
    SprayOptimizer,
    SprayPolicy,
    CredentialMatch,
    SprayAttempt
)

__all__ = ["SprayOptimizer", "SprayPolicy", "CredentialMatch", "SprayAttempt"]
