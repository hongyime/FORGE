from __future__ import annotations

from forge.phase4 import cloud_validate


class _FakeResponse:
    def __init__(self, status_code: int, text: str, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "text/html"}


class _HeadThenGetClient:
    calls: list[tuple[str, str]] = []

    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_HeadThenGetClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        self.calls.append(("HEAD", url))
        return _FakeResponse(200, "")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        self.calls.append(("GET", url))
        return _FakeResponse(200, "Deployment Not Found")


class _HeadWithBodyClient(_HeadThenGetClient):
    calls: list[tuple[str, str]] = []

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        self.calls.append(("HEAD", url))
        return _FakeResponse(200, "<html>active app</html>")


def test_managed_hosting_reachability_gets_empty_successful_head_for_placeholder_detection(
    monkeypatch,
) -> None:
    _HeadThenGetClient.calls = []
    monkeypatch.setattr(cloud_validate.httpx, "Client", _HeadThenGetClient)

    result = cloud_validate.ManagedHostingReachabilityValidator("vercel", "vercel.app").validate(
        "acme-preview"
    )

    assert _HeadThenGetClient.calls == [
        ("HEAD", "https://acme-preview.vercel.app"),
        ("GET", "https://acme-preview.vercel.app"),
    ]
    assert result.validation_status == "UNVERIFIED"
    assert "placeholder" in result.notes.lower()


def test_managed_hosting_reachability_keeps_body_bearing_head_without_extra_get(
    monkeypatch,
) -> None:
    _HeadWithBodyClient.calls = []
    monkeypatch.setattr(cloud_validate.httpx, "Client", _HeadWithBodyClient)

    result = cloud_validate.ManagedHostingReachabilityValidator("netlify", "netlify.app").validate(
        "acme-edge"
    )

    assert _HeadWithBodyClient.calls == [("HEAD", "https://acme-edge.netlify.app")]
    assert result.validation_status == "ACCESSIBLE_BUT_NO_DATA"
