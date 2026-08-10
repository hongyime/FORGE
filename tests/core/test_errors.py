"""Tests for forge.core.errors — Platform error hierarchy."""

from __future__ import annotations

import pytest

from forge.core.errors import (
    CheckpointCorruptedError,
    ForgeError,
    GovernanceDeniedError,
    PluginTimeoutError,
    PluginValidationError,
    ProviderUnavailableError,
    ScopeViolationError,
    WorkflowFailedError,
)


class TestErrorHierarchy:
    """All platform errors inherit from ForgeError."""

    @pytest.mark.parametrize(
        "error_cls",
        [
            ProviderUnavailableError,
            PluginTimeoutError,
            PluginValidationError,
            WorkflowFailedError,
            GovernanceDeniedError,
            CheckpointCorruptedError,
        ],
    )
    def test_inherits_from_forge_error(self, error_cls: type[ForgeError]) -> None:
        """Each error class is a subclass of ForgeError."""
        assert issubclass(error_cls, ForgeError)
        assert issubclass(error_cls, Exception)

    def test_forge_error_is_base(self) -> None:
        """ForgeError itself inherits from Exception."""
        assert issubclass(ForgeError, Exception)

    @pytest.mark.parametrize(
        "error_cls",
        [
            ProviderUnavailableError,
            PluginTimeoutError,
            PluginValidationError,
            WorkflowFailedError,
            GovernanceDeniedError,
            CheckpointCorruptedError,
        ],
    )
    def test_can_be_raised_and_caught_as_forge_error(self, error_cls: type[ForgeError]) -> None:
        """Errors can be caught with a ForgeError handler."""
        with pytest.raises(ForgeError):
            raise error_cls("test message")


class TestScopeViolationError:
    """ScopeViolationError carries target and scope attributes."""

    def test_attributes(self) -> None:
        """ScopeViolationError stores target and scope."""
        # Use a mock-like object for scope since EngagementScope isn't defined yet
        from unittest.mock import MagicMock

        mock_scope = MagicMock()
        mock_scope.domains = ["example.com"]

        err = ScopeViolationError(target="evil.com", scope=mock_scope)

        assert err.target == "evil.com"
        assert err.scope is mock_scope
        assert "evil.com" in str(err)

    def test_inherits_from_forge_error(self) -> None:
        """ScopeViolationError is a ForgeError."""
        assert issubclass(ScopeViolationError, ForgeError)

    def test_can_be_caught_as_forge_error(self) -> None:
        """ScopeViolationError can be caught with ForgeError handler."""
        from unittest.mock import MagicMock

        with pytest.raises(ForgeError):
            raise ScopeViolationError(target="10.0.0.1", scope=MagicMock())


class TestErrorMessages:
    """Errors can carry descriptive messages."""

    def test_provider_unavailable_message(self) -> None:
        err = ProviderUnavailableError("llama-cpp timed out after 5s")
        assert "llama-cpp timed out after 5s" in str(err)

    def test_plugin_timeout_message(self) -> None:
        err = PluginTimeoutError("nmap exceeded 300s timeout")
        assert "nmap exceeded 300s timeout" in str(err)

    def test_plugin_validation_message(self) -> None:
        err = PluginValidationError("missing 'version' field in metadata")
        assert "missing 'version' field" in str(err)

    def test_workflow_failed_message(self) -> None:
        err = WorkflowFailedError("discovery stage exhausted 3 retries")
        assert "discovery stage exhausted 3 retries" in str(err)

    def test_governance_denied_message(self) -> None:
        err = GovernanceDeniedError("exploit execution blocked by policy")
        assert "exploit execution blocked by policy" in str(err)

    def test_checkpoint_corrupted_message(self) -> None:
        err = CheckpointCorruptedError("CRC mismatch on workflow w-001")
        assert "CRC mismatch" in str(err)
