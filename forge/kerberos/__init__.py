"""FORGE Kerberos Package.

Kerberos ticket operations for authorized red team operations.

Security: All Kerberos operations require explicit ROE + scope manifest.
"""

from .kerberos_ops import KerberosOps, KerberosTicket

__all__ = ["KerberosOps", "KerberosTicket"]
