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
        '{"sid":"AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3",'
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
        "AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3",
        auth_token="auth-token",
    )

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == (
        "Twilio account not active: "
        f"Twilio account accessible: sid=AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3 "
        f"status={status} type=Full"
    )
