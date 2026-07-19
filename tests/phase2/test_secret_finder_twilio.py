from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest

from forge.utils.intel.secret_finder import TwilioKeyValidator, ValidationState


class _TwilioClient:
    def __enter__(self) -> "_TwilioClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb


class _SessionFactory:
    def __call__(self, *args, **kwargs) -> _TwilioClient:  # noqa: ANN002, ANN003
        del args, kwargs
        return _TwilioClient()


@pytest.mark.parametrize("status", ["suspended", "closed"])
def test_twilio_validator_non_active_account_status_stays_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    response = MagicMock()
    response.status_code = 200
    response.text = (
        '{"sid":"AC1234567890abcdef1234567890abcdef",'
        f'"status":"{status}","type":"Full"}}'
    )
    fake_requests = types.SimpleNamespace(Session=_SessionFactory())
    monkeypatch.setitem(sys.modules, "curl_cffi", types.SimpleNamespace(requests=fake_requests))
    monkeypatch.setitem(sys.modules, "curl_cffi.requests", fake_requests)
    monkeypatch.setattr(
        "forge.utils.intel.secret_finder.key_validation_get",
        lambda *args, **kwargs: response,  # noqa: ARG005
    )

    result = TwilioKeyValidator().validate(
        "AC1234567890abcdef1234567890abcdef",
        auth_token="auth-token",
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == (
        "Twilio account not active: "
        f"Twilio account accessible: sid=AC1234567890abcdef1234567890abcdef "
        f"status={status} type=Full"
    )
