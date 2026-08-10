"""
forge/utils/intel/auth_adapters/__init__.py
Canonical: forge/phase2/auth_adapters/__init__.py

BaseAuthAdapter ABC consumed by Module 2-B CredentialValidator.
All adapters are fully async and return (success: bool, error: Optional[str]).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class BaseAuthAdapter(ABC):
    """
    Protocol-specific authentication adapter.

    Contract:
      - authenticate() NEVER stores or logs the password parameter.
      - Must be safe to call concurrently (asyncio.Semaphore is managed by caller).
      - Returns (True, None) on success.
      - Returns (False, error_message) on any failure, including timeout and scope error.
      - Must not raise; all exceptions must be caught and returned as (False, str(exc)).
    """

    @abstractmethod
    async def authenticate(
        self,
        host: str,
        username: str,
        password: str,
        port: Optional[int] = None,
        **kwargs,
    ) -> tuple[bool, Optional[str]]: ...

    @property
    def default_port(self) -> int:
        return 0

    @property
    def service_name(self) -> str:
        return self.__class__.__name__.replace("Adapter", "").lower()
