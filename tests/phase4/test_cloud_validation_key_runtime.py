from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.phase4 import cloud_validate


class _FakeResponse:
    def __init__(self, status_code: int, text: str, headers: dict | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "application/json"}


class _FirebaseClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_FirebaseClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "init.json" in url:
            return _FakeResponse(200, '{"projectId":"acme-firebase-prod","appId":"1:test:web"}')
        return _FakeResponse(404, "missing")


def _bootstrap_db(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()


def test_run_cloud_validate_persists_result_and_updates_key_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, validation_state)
            VALUES
                (1, 1001, 'acme-firebase-prod', 'firebase', 'firebase_web_config', 'crawler',
                 'https://acme-firebase-prod.firebaseapp.com/__/firebase/init.json',
                 'webapp', 'AIza...7890', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(cloud_validate.httpx, "Client", _FirebaseClient)

    result = cloud_validate.run_cloud_validate(1, "test_bucket", 10, db_path)

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert result["identifier"] == "acme-firebase-prod"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("firebase", "acme-firebase-prod", "ACCESSIBLE_BUT_NO_DATA")

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail, validated_at
            FROM key_scanner_findings
            WHERE id=1
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert "ACCESSIBLE_BUT_NO_DATA:firebase_init_json" in str(key_row[1])
        assert key_row[2] is not None
    finally:
        con.close()


def test_run_cloud_validate_respects_scheduled_rate_limit_before_provider(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, validation_state)
            VALUES
                (2, 1001, 'acme-firebase-prod', 'firebase', 'firebase_web_config', 'crawler',
                 'https://acme-firebase-prod.firebaseapp.com/__/firebase/init.json',
                 'webapp', 'AIza...7890', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    class _DenyLimiter:
        def acquire(self, bucket_name: str, max_requests: int, window_seconds: int = 60) -> bool:
            assert bucket_name == "cloud_api_global"
            assert max_requests == 1
            assert window_seconds == 60
            return False

    def _fail_validate_key_row_payload(row_payload, **kwargs):  # noqa: ANN001
        del row_payload, kwargs
        raise AssertionError("rate-limited validation must not reach provider validation")

    monkeypatch.setattr(cloud_validate, "_validate_key_row_payload", _fail_validate_key_row_payload)

    result = cloud_validate.run_cloud_validate(
        2,
        "cloud_api_global",
        1,
        db_path,
        rate_limiter=_DenyLimiter(),
    )

    assert result == {
        "status": "rate_limited",
        "error": "rate limit bucket 'cloud_api_global' exhausted.",
        "key_id": 2,
        "rate_limit_bucket": "cloud_api_global",
    }
    con = sqlite3.connect(db_path)
    try:
        assert con.execute("SELECT COUNT(*) FROM cloud_validation_results").fetchone()[0] == 0
        assert con.execute(
            "SELECT validation_state FROM key_scanner_findings WHERE id=2"
        ).fetchone()[0] == "UNCONFIRMED"
    finally:
        con.close()


def test_run_cloud_validate_scope_checker_skips_denied_key_row(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name,
                 key_redacted, key_enc, validation_state)
            VALUES
                (83, 1001, 'evil.example', 'stripe', 'stripe_live_secret_key', 'crawler',
                 'https://evil.example/config.js', 'webapp', 'sk_live_...1234',
                 'ciphertext-placeholder', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    def _fail_validate_key_row_payload(row_payload, **kwargs):  # noqa: ANN001
        del row_payload, kwargs
        raise AssertionError("scope-denied key row must not reach provider validation")

    denied_callbacks: list[tuple[int, str]] = []
    monkeypatch.setattr(cloud_validate, "_validate_key_row_payload", _fail_validate_key_row_payload)

    result = cloud_validate.run_cloud_validate(
        83,
        "test_bucket",
        10,
        db_path,
        key_scope_checker=lambda row_payload: False,
        key_scope_denied_callback=lambda row_payload, reason: denied_callbacks.append(
            (int(row_payload["id"]), reason)
        ),
    )

    assert denied_callbacks == [(83, "scope_manifest_denied")]
    assert result["status"] == "success"
    assert result["validation_status"] == "UNVERIFIED"
    assert result["validation_method"] == "scope_manifest"
    assert result["identifier"] == "https://evil.example/config.js"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method, evidence, notes
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "stripe",
            "https://evil.example/config.js",
            "UNVERIFIED",
            "scope_manifest",
            "scope denied before key validation",
            "scope_manifest_denied",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail, validated_at
            FROM key_scanner_findings
            WHERE id=83
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1]).startswith("UNVERIFIED:scope_manifest:scope_manifest_denied")
        assert key_row[2] is not None
    finally:
        con.close()


def test_scheduled_validate_task_scope_manifest_denies_out_of_scope_key_row(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from forge.distributed.runnable import run_scheduled_task

    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name,
                 key_redacted, key_enc, validation_state)
            VALUES
                (84, 1001, 'evil.example', 'stripe', 'stripe_live_secret_key', 'crawler',
                 'https://evil.example/config.js', 'webapp', 'sk_live_...1234',
                 'ciphertext-placeholder', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    def _fail_validate_key_row_payload(row_payload, **kwargs):  # noqa: ANN001
        del row_payload, kwargs
        raise AssertionError("scope-denied scheduled key row must not reach provider validation")

    monkeypatch.setattr(cloud_validate, "_validate_key_row_payload", _fail_validate_key_row_payload)

    run_scheduled_task(
        1001,
        "validate:84",
        {
            "task_type": "validate",
            "key_id": 84,
            "scope_manifest": json.dumps(
                {
                    "roe_id": "ROE-ACME-2026-07",
                    "domains": ["allowed.example"],
                    "urls": ["https://allowed.example"],
                }
            ),
            "roe_id": "ROE-ACME-2026-07",
            "require_scope_manifest": True,
        },
        db_path,
    )

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method, evidence, notes
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "stripe",
            "https://evil.example/config.js",
            "UNVERIFIED",
            "scope_manifest",
            "scope denied before key validation",
            "scope_manifest_denied",
        )
    finally:
        con.close()


def test_run_cloud_validate_marks_unsupported_without_identifier(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, validation_state)
            VALUES
                (2, 1001, '', 'stripe', 'publishable_key', 'crawler',
                 'README.txt', 'notes', 'pk_live_1234', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    result = cloud_validate.run_cloud_validate(2, "test_bucket", 10, db_path)

    assert result["status"] == "success"
    assert result["validation_status"] == "UNSUPPORTED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("stripe", "UNSUPPORTED")

        key_state = con.execute(
            "SELECT validation_state FROM key_scanner_findings WHERE id=2"
        ).fetchone()[0]
        assert key_state == "UNCONFIRMED"
    finally:
        con.close()
