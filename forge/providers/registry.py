"""
forge/providers/registry.py — Provider discovery, validation, and hot-loading.

Implements the :class:`ProviderRegistry` used by the Provider Abstraction Layer
to map a configured backend name (``llama_cpp``, ``ollama``, ``vllm``,
``openai_compatible``, …) to a concrete :class:`~forge.providers.base.LLMProvider`
instance. Built-in factories are seeded lazily so importing this module does
not require every backend library to be installed; only the factory whose name
matches ``FORGE_LLM_PROVIDER`` is invoked at startup.

Each candidate produced by a factory is validated against the runtime-checkable
:class:`~forge.providers.base.LLMProvider` protocol. Candidates that fail the
check are rejected and logged to the audit trail rather than being silently
returned to callers.

Operators may extend the registry without modifying this module by calling
:meth:`ProviderRegistry.register` with a factory callable. Duplicate names are
rejected by default; pass ``replace=True`` to overwrite an existing entry.

Validates: Requirements 3.5
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import TYPE_CHECKING, Callable

from forge.audit.models import AuditEntry, AuditEventType
from forge.providers.base import LLMProvider

if TYPE_CHECKING:
    from forge.audit.logger import AuditLogger

__all__ = ["ProviderFactory", "ProviderRegistry"]

_LOG = logging.getLogger(__name__)

#: Type alias for a zero-argument factory that returns an :class:`LLMProvider`.
ProviderFactory = Callable[[], LLMProvider]


# ── Built-in factories ────────────────────────────────────────────────────────
#
# Each built-in factory is implemented as a lightweight closure that imports
# the backend module *only when called*. Importing ``forge.providers.registry``
# therefore does not pull in ``llama_cpp_python``, ``ollama``, ``vllm``, or any
# OpenAI-compatible client library. Only the factory whose name matches the
# active provider is ever invoked.


def _llama_cpp_factory() -> LLMProvider:
    """Lazy factory for the llama-cpp-python provider (task 5.2).

    Imports :mod:`forge.providers.llama_cpp` and :mod:`forge.config` on first
    invocation and instantiates :class:`LlamaCppProvider` with values sourced
    from :class:`~forge.config.PlatformSettings`. Kept lazy so this module can
    be imported in environments where ``llama-cpp-python`` is not installed.

    Raises:
        ProviderUnavailableError: When ``FORGE_LLM_MODEL_PATH`` is unset.
    """
    from forge.config import PlatformSettings  # noqa: PLC0415
    from forge.core.errors import ProviderUnavailableError  # noqa: PLC0415
    from forge.providers.llama_cpp import LlamaCppProvider  # noqa: PLC0415

    settings = PlatformSettings()
    if not settings.llm_model_path:
        raise ProviderUnavailableError(
            "FORGE_LLM_MODEL_PATH must be set when FORGE_LLM_PROVIDER=llama_cpp."
        )
    return LlamaCppProvider(
        model_path=settings.llm_model_path,
        timeout=float(settings.provider_timeout),
    )


def _ollama_factory() -> LLMProvider:
    """Stub factory for the Ollama backend.

    Raises :class:`NotImplementedError` until the Ollama backend is delivered
    in a follow-up task. Operators wishing to use Ollama today must register
    their own factory via :meth:`ProviderRegistry.register`.
    """
    raise NotImplementedError(
        "The 'ollama' provider is not yet implemented. "
        "Register a custom factory via ProviderRegistry.register('ollama', ...) "
        "or set FORGE_LLM_PROVIDER=llama_cpp for the MVP backend."
    )


def _vllm_factory() -> LLMProvider:
    """Stub factory for the vLLM backend.

    Raises :class:`NotImplementedError` until the vLLM backend is delivered in
    a follow-up task.
    """
    raise NotImplementedError(
        "The 'vllm' provider is not yet implemented. "
        "Register a custom factory via ProviderRegistry.register('vllm', ...) "
        "or set FORGE_LLM_PROVIDER=llama_cpp for the MVP backend."
    )


def _openai_compatible_factory() -> LLMProvider:
    """Stub factory for OpenAI-compatible HTTP endpoints.

    Raises :class:`NotImplementedError` until the OpenAI-compatible backend is
    delivered in a follow-up task.
    """
    raise NotImplementedError(
        "The 'openai_compatible' provider is not yet implemented. "
        "Register a custom factory via "
        "ProviderRegistry.register('openai_compatible', ...) "
        "or set FORGE_LLM_PROVIDER=llama_cpp for the MVP backend."
    )


_BUILTIN_FACTORIES: dict[str, ProviderFactory] = {
    "llama_cpp": _llama_cpp_factory,
    "ollama": _ollama_factory,
    "vllm": _vllm_factory,
    "openai_compatible": _openai_compatible_factory,
}


# ── Registry ──────────────────────────────────────────────────────────────────


class ProviderRegistry:
    """Discovery, validation, and retrieval of LLM provider implementations.

    The registry seeds the four built-in backend names (``llama_cpp``,
    ``ollama``, ``vllm``, ``openai_compatible``) lazily so importing this
    module never forces backend libraries to be installed. Operators add
    custom backends by calling :meth:`register`.

    Args:
        audit: Optional audit logger. When provided, registration and
            rejection events are emitted as
            :attr:`~forge.audit.models.AuditEventType.STATE_TRANSITION`
            entries with secrets redacted by the logger itself.
        seed_builtins: When ``True`` (the default) the registry pre-registers
            the four built-in backend factories. Set to ``False`` to start
            with an empty registry, useful in tests that want full control
            over the available names.
    """

    def __init__(
        self,
        audit: "AuditLogger | None" = None,
        *,
        seed_builtins: bool = True,
    ) -> None:
        self._factories: dict[str, ProviderFactory] = {}
        self._instances: dict[str, LLMProvider] = {}
        self._audit = audit
        if seed_builtins:
            for name, factory in _BUILTIN_FACTORIES.items():
                # Built-ins bypass the public register() audit emission so the
                # registry can be constructed in cold-start paths without
                # producing a flood of registration events; their presence is
                # implicit in the platform contract.
                self._factories[name] = factory

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(
        self,
        name: str,
        factory: ProviderFactory,
        *,
        replace: bool = False,
    ) -> None:
        """Register an additional provider factory.

        Args:
            name: The key used by ``FORGE_LLM_PROVIDER`` and :meth:`get`.
            factory: Zero-argument callable that returns an
                :class:`LLMProvider` instance. The factory is invoked the
                first time :meth:`get` is called for ``name``.
            replace: When ``True``, overwrites any existing factory bound to
                ``name``. Defaults to ``False`` so accidental shadowing of a
                built-in backend raises immediately.

        Raises:
            ValueError: ``name`` is empty or already registered (when
                ``replace`` is False).
            TypeError: ``factory`` is not callable.
        """
        if not name or not isinstance(name, str):
            raise ValueError("Provider name must be a non-empty string.")
        if not callable(factory):
            raise TypeError(
                f"Provider factory for {name!r} must be callable, got {type(factory).__name__}."
            )
        if not replace and name in self._factories:
            raise ValueError(
                f"Provider {name!r} is already registered. Pass replace=True to overwrite."
            )

        self._factories[name] = factory
        # Replacing also invalidates any cached instance so the next get()
        # call exercises the fresh factory.
        self._instances.pop(name, None)
        self._emit_audit(
            event_type=AuditEventType.STATE_TRANSITION,
            output_summary=f"provider_registered:{name}",
            input_params={"provider_name": name, "replace": replace},
        )
        _LOG.debug("Registered provider factory: %s (replace=%s)", name, replace)

    def get(self, name: str) -> LLMProvider:
        """Resolve ``name`` to an :class:`LLMProvider` instance.

        The factory bound to ``name`` is invoked on first call and the result
        is cached for subsequent retrievals. The candidate is validated
        against the runtime-checkable :class:`LLMProvider` protocol; any
        candidate that fails the check is rejected, logged to the audit
        trail, and a :class:`TypeError` is raised.

        Args:
            name: Registered provider name.

        Returns:
            The cached :class:`LLMProvider` instance.

        Raises:
            KeyError: ``name`` is not registered.
            TypeError: The factory returned an object that does not satisfy
                the :class:`LLMProvider` protocol.
        """
        cached = self._instances.get(name)
        if cached is not None:
            return cached

        factory = self._factories.get(name)
        if factory is None:
            available = ", ".join(sorted(self._factories)) or "<none>"
            raise KeyError(
                f"No provider registered under name {name!r}. Available providers: {available}."
            )

        candidate = factory()
        if not isinstance(candidate, LLMProvider):
            reason = (
                f"Provider {name!r} factory returned object of type "
                f"{type(candidate).__name__!r} which does not implement the "
                "LLMProvider protocol (missing one of: complete, "
                "structured_output, embed, health_check)."
            )
            self._emit_audit(
                event_type=AuditEventType.WARNING,
                output_summary=f"provider_rejected:{name}",
                input_params={"provider_name": name, "reason": reason},
                success=False,
                error_detail=reason,
            )
            _LOG.warning(reason)
            raise TypeError(reason)

        self._instances[name] = candidate
        return candidate

    def get_active(self) -> LLMProvider:
        """Return the provider named by ``PlatformSettings.llm_provider``.

        Reads the configured backend name from the environment via
        :class:`forge.config.PlatformSettings` (which is itself
        environment-variable-only, never auto-loading ``.env``) and resolves
        it through :meth:`get`.
        """
        # Imported lazily so this module does not depend on
        # pydantic-settings at import time. It is already a runtime dep of
        # the platform but the lazy import keeps the registry usable in
        # narrow unit tests that monkey-patch the configuration source.
        from forge.config import PlatformSettings  # noqa: PLC0415

        settings = PlatformSettings()
        return self.get(settings.llm_provider)

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._factories

    def list_providers(self) -> list[str]:
        """Return the sorted list of registered provider names."""
        return sorted(self._factories)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _emit_audit(
        self,
        *,
        event_type: AuditEventType,
        output_summary: str,
        input_params: dict[str, object],
        success: bool = True,
        error_detail: str | None = None,
    ) -> None:
        """Best-effort audit emission used by registration and rejection."""
        if self._audit is None:
            return
        entry = AuditEntry(
            timestamp_utc=time.time(),
            correlation_id=f"provider-registry:{uuid.uuid4()}",
            event_type=event_type,
            agent_role="provider_registry",
            tool_name=None,
            input_params=input_params,
            output_summary=output_summary,
            duration_ms=None,
            success=success,
            error_detail=error_detail,
        )
        # ``AuditLogger.log`` is async; schedule it without forcing the
        # caller to be inside an event loop. If no loop is running we run
        # the coroutine synchronously to completion.
        import asyncio  # noqa: PLC0415

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self._audit.log(entry))
            return
        loop.create_task(self._audit.log(entry))
