"""Session enumeration collection helpers for authorized post-exploitation evidence.

Exports the public session enumeration functions and types for Windows
(NetSessionEnum) and Linux (who/w/last) targets.  All enumeration is
scope-gated; callers MUST supply engagement_id, scope_manifest, and db_path.
"""

from forge.collection.sessions.linux_sessions import Session, collect_linux_sessions
from forge.collection.sessions.scope_check import (
    SessionEnumerationAuditError,
    SessionEnumerationScopeError,
    enumerate_sessions_scoped,
)
from forge.collection.sessions.windows_sessions import enumerate_sessions

__all__ = [
    "Session",
    "SessionEnumerationAuditError",
    "SessionEnumerationScopeError",
    "collect_linux_sessions",
    "enumerate_sessions",
    "enumerate_sessions_scoped",
]
