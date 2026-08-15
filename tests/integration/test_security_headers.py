from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from forge.api.app import create_app as create_api_app
from forge.api.deps import reset_dependencies
from forge.webui.app import create_app as create_webui_app


def _configure_production_env(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "production")
    monkeypatch.setenv("FORGE_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("FORGE_PUBLIC_BASE_URL", "https://forge.example.test")
    monkeypatch.setenv("FORGE_TLS_TERMINATED_BY", "reverse-proxy")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "s" * 64)
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.setenv("FORGE_AUDIT_LOG_DISABLE", "1")
    monkeypatch.setenv("FORGE_STATE_DB_URL", f"sqlite:///{tmp_path / 'state.db'}")


def _assert_common_headers(headers: object) -> None:
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert "camera=()" in headers["permissions-policy"]
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]


def test_platform_api_sets_production_security_headers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_production_env(tmp_path, monkeypatch)
    reset_dependencies()
    try:
        app = create_api_app()
        with TestClient(app) as client:
            response = client.get("/ready")
    finally:
        reset_dependencies()

    assert response.status_code == 200
    _assert_common_headers(response.headers)
    assert response.headers["strict-transport-security"].startswith("max-age=31536000")
    assert "default-src 'none'" in response.headers["content-security-policy"]


def test_webui_sets_production_security_headers(tmp_path: Path, monkeypatch) -> None:
    _configure_production_env(tmp_path, monkeypatch)
    app = create_webui_app()
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    _assert_common_headers(response.headers)
    assert response.headers["strict-transport-security"].startswith("max-age=31536000")
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_hsts_is_skipped_for_local_profiles(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "s" * 64)
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")

    app = create_webui_app()
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    _assert_common_headers(response.headers)
    assert "strict-transport-security" not in response.headers
