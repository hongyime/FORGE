from __future__ import annotations

import json
import sqlite3
import time
import zipfile
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from threading import Thread

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


_MEGA_SCOPE_JSON = (
    '["*.acme.example","+15551234567","security@acme.example",'
    '"https://downloads.acme.example/app.apk"]'
)


def _bootstrap_mega_shape(db_path: Path) -> None:
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json=_MEGA_SCOPE_JSON,
        operator="delta-one",
    )


def run_extensionless_remote_dex_download(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path)

    dex_bytes = (
        b"dex\n035\x00"
        b"remote-dex@acme.example\x00"
        b"https://remote-dex.acme.example/api\x00"
        b"https://remote-dex-firebase.firebaseio.com\x00"
        b"s3://remote-dex-bucket/mobile/classes.dex\x00"
    )

    class _DownloadHandler(SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return None

        def do_GET(self) -> None:  # noqa: N802
            if self.path.startswith("/opaque-compiled"):
                self.send_response(200)
                self.send_header("Content-Type", "application/x-dex")
                self.send_header("Content-Length", str(len(dex_bytes)))
                self.end_headers()
                self.wfile.write(dex_bytes)
                return
            self.send_error(404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _DownloadHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        source_url = f"http://127.0.0.1:{server.server_address[1]}/opaque-compiled?id=42"
        con = sqlite3.connect(db_path)
        try:
            con.execute(
                """
                INSERT INTO engagement_seeds
                    (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
                VALUES
                    (1001, ?, 'url', 'scope', 'pending', 0, 0.88, '{}')
                """,
                (source_url,),
            )
            con.execute(
                """
                INSERT INTO artifact_queue
                    (engagement_id, source_url, artifact_type, discovered_from, status, metadata_json)
                VALUES
                    (1001, ?, 'document', 'engagement_seed', 'queued', '{}')
                """,
                (source_url,),
            )
            con.commit()
        finally:
            con.close()

        summary = ArtifactQueueProcessor(db_path, 1001).process()
        assert summary.processed == 1
        assert summary.discovered_seeds >= 2

        con = sqlite3.connect(db_path)
        try:
            artifact_row = con.execute(
                """
                SELECT status, local_path, artifact_type, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001 AND source_url=?
                """,
                (source_url,),
            ).fetchone()
            assert artifact_row is not None
            assert artifact_row[0] == "parsed"
            assert artifact_row[2] == "document"
            local_path = Path(str(artifact_row[1]))
            assert local_path.exists()
            assert local_path.suffix.lower() == ".dex"
            metadata = json.loads(str(artifact_row[3] or "{}"))
            assert metadata["format"] == "dex"
            assert metadata["content_type"] == "application/x-dex"
            assert metadata["download_filename"].endswith(".dex")
            assert metadata["payload_count"] >= 1

            seeds = {
                (row[0], row[1])
                for row in con.execute(
                    """
                    SELECT seed_value, seed_type
                    FROM engagement_seeds
                    WHERE engagement_id=1001
                    """
                ).fetchall()
            }
            assert ("remote-dex@acme.example", "email") in seeds
            assert ("https://remote-dex.acme.example/api", "url") in seeds

            provenance_rows = {
                row[0]: (json.loads(str(row[1] or "{}")), json.loads(str(row[2] or "{}")))
                for row in con.execute(
                    """
                    SELECT target.seed_value, sr.evidence_json, target.metadata_json
                    FROM seed_relations sr
                    JOIN engagement_seeds source ON source.id=sr.source_seed_id
                    JOIN engagement_seeds target ON target.id=sr.target_seed_id
                    WHERE sr.engagement_id=1001
                      AND source.seed_value=?
                      AND sr.relation_type='derived_from'
                    """,
                    (source_url,),
                ).fetchall()
            }
            email_evidence, email_seed_metadata = provenance_rows["remote-dex@acme.example"]
            assert email_evidence["rule"] == "artifact_seed_provenance"
            assert email_evidence["extract_rule"] == "artifact_text_extract"
            assert email_evidence["format"] == "dex"
            assert email_evidence["content_type"] == "application/x-dex"
            assert email_evidence["download_filename"].endswith(".dex")
            assert email_evidence["downloaded_from_remote"] is True
            assert email_evidence["payload_count"] >= 1
            assert email_seed_metadata["artifact_provenance"] is True
            assert email_seed_metadata["artifact_type"] == "document"
            assert email_seed_metadata["format"] == "dex"
            assert email_seed_metadata["content_type"] == "application/x-dex"
            assert email_seed_metadata["download_filename"].endswith(".dex")
            assert email_seed_metadata["downloaded_from_remote"] is True

            cloud_assets = con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                ORDER BY asset_type, identifier
                """
            ).fetchall()
            assert ("aws_s3", "remote-dex-bucket") in cloud_assets
            assert ("firebase", "remote-dex-firebase") in cloud_assets
        finally:
            con.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def run_remote_mobile_bundle_url_seed(
    tmp_path: Path,
    monkeypatch,  # noqa: ANN001
    *,
    served_dir: str,
    filename: str,
    bundle_format: str,
    firebase_project: str,
    supabase_ref: str,
    supabase_anon: str,
    owner_email: str,
    endpoint_url: str,
    archive_entries: tuple[tuple[str, bytes | str], ...],
    require_nested_count: bool,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")

    served_root = tmp_path / served_dir
    served_root.mkdir()
    remote_bundle = served_root / filename

    base_apk_bytes = BytesIO()
    with zipfile.ZipFile(base_apk_bytes, "w") as zf:
        zf.writestr(
            "google-services.json",
            f"""
            {{
              "project_info": {{
                "project_id": "{firebase_project}",
                "firebase_url": "https://{firebase_project}.firebaseio.com"
              }}
            }}
            """.strip(),
        )
        zf.writestr(
            "assets/supabase.js",
            f"""
            export const url = "https://{supabase_ref}.supabase.co";
            export const anon = "{supabase_anon}";
            export const owner = "{owner_email}";
            export const endpoint = "{endpoint_url}";
            """.strip(),
        )

    with zipfile.ZipFile(remote_bundle, "w") as zf:
        for name, payload in archive_entries:
            zf.writestr(name, base_apk_bytes.getvalue() if payload == "{base_apk}" else payload)

    class _QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return None

    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        partial(_QuietHandler, directory=str(served_root)),
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _bootstrap_mega_shape(db_path)
        source_url = f"http://127.0.0.1:{server.server_address[1]}/{filename}?download=1"

        con = sqlite3.connect(db_path)
        try:
            con.execute(
                """
                INSERT INTO engagement_seeds
                    (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
                VALUES
                    (1001, ?, 'url', 'cross_reference', 'pending', 1, 0.82, '{}')
                """,
                (source_url,),
            )
            con.commit()
        finally:
            con.close()

        from forge.cli import kill_chain

        kill_chain(
            seed="acme.example",
            related_seed=["security@acme.example"],
            engagement="1001",
            max_iter=1,
            tor=False,
            dry_run=True,
            attack_mode=False,
            skip_cloud=True,
            skip_keyscan=True,
        )

        con = sqlite3.connect(db_path)
        try:
            artifact_row = con.execute(
                """
                SELECT status, local_path, discovered_from, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001 AND source_url=?
                """,
                (source_url,),
            ).fetchone()
            assert artifact_row is not None
            assert artifact_row[0] == "parsed"
            assert artifact_row[2] == "engagement_seed"
            assert artifact_row[1]
            assert Path(str(artifact_row[1])).exists()
            metadata = json.loads(str(artifact_row[3] or "{}"))
            assert metadata["format"] == bundle_format
            if require_nested_count:
                assert metadata["nested_mobile_member_count"] >= 1

            cloud_assets = {
                (row[0], row[1])
                for row in con.execute(
                    """
                    SELECT asset_type, identifier
                    FROM cloud_assets
                    WHERE engagement_id=1001
                    """
                ).fetchall()
            }
            assert ("firebase", firebase_project) in cloud_assets
            assert ("supabase", supabase_ref) in cloud_assets

            relations = {
                (str(row[0]), str(row[1]), str(row[2]))
                for row in con.execute(
                    """
                    SELECT src.seed_value, dst.seed_value, sr.relation_type
                    FROM seed_relations sr
                    JOIN engagement_seeds src ON src.id=sr.source_seed_id
                    JOIN engagement_seeds dst ON dst.id=sr.target_seed_id
                    WHERE sr.engagement_id=1001
                    """
                ).fetchall()
            }
            assert (source_url, firebase_project, "derived_from") in relations
            assert (source_url, supabase_ref, "derived_from") in relations

            seeds = {
                (str(row[0]), str(row[1]))
                for row in con.execute(
                    """
                    SELECT seed_value, seed_type
                    FROM engagement_seeds
                    WHERE engagement_id=1001
                    """
                ).fetchall()
            }
            assert (owner_email, "email") in seeds
            assert (endpoint_url, "url") in seeds
        finally:
            con.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def run_rate_limited_remote_artifact_retry(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    from forge.utils.intel import http_pacing

    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setenv("FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS", "0")
    monkeypatch.setenv("FORGE_WEB_FETCH_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setenv("FORGE_WEB_FETCH_RATE_LIMIT_BACKOFF_SECONDS", "1")
    monkeypatch.setenv("FORGE_WEB_FETCH_MAX_RETRY_AFTER_SECONDS", "1")

    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path)
    image_bytes = b"\x89PNG\r\n\x1a\nrate-limited-remote-image"
    request_count = {"value": 0}

    def _fake_ocr_path(_self, path: Path) -> str:  # noqa: ANN001
        if path.suffix.lower() == ".png":
            return "retry-ocr@acme.example https://retry.acme.example/poster"
        return ""

    monkeypatch.setattr(ArtifactQueueProcessor, "_ocr_image_path", _fake_ocr_path)

    class _RateLimitedDownloadHandler(SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return None

        def do_GET(self) -> None:  # noqa: N802
            request_count["value"] += 1
            if request_count["value"] == 1:
                self.send_response(429)
                self.send_header("Retry-After", "1")
                self.end_headers()
                return
            if self.path.startswith("/artifact"):
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="retry-briefing.png"',
                )
                self.send_header("Content-Length", str(len(image_bytes)))
                self.end_headers()
                self.wfile.write(image_bytes)
                return
            self.send_error(404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _RateLimitedDownloadHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda seconds: sleeps.append(float(seconds)))
    try:
        source_url = f"http://127.0.0.1:{server.server_address[1]}/artifact?id=42"
        con = sqlite3.connect(db_path)
        try:
            con.execute(
                """
                INSERT INTO artifact_queue
                    (engagement_id, source_url, artifact_type, discovered_from, status, metadata_json)
                VALUES
                    (1001, ?, 'document', 'engagement_seed', 'queued', '{}')
                """,
                (source_url,),
            )
            con.commit()
        finally:
            con.close()

        summary = ArtifactQueueProcessor(db_path, 1001).process()
        assert summary.processed == 1
        assert request_count["value"] == 2
        assert sleeps == [1.0]

        con = sqlite3.connect(db_path)
        try:
            artifact_row = con.execute(
                """
                SELECT status, local_path, artifact_type, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001 AND source_url=?
                """,
                (source_url,),
            ).fetchone()
            assert artifact_row is not None
            assert artifact_row[0] == "parsed"
            assert artifact_row[2] == "document"
            local_path = Path(str(artifact_row[1]))
            assert local_path.exists()
            assert local_path.suffix.lower() == ".png"
            metadata = json.loads(str(artifact_row[3] or "{}"))
            assert metadata["format"] == "png"
            assert metadata["download_filename"].endswith("retry-briefing.png")
            assert metadata["ocr_payload_count"] >= 1
        finally:
            con.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        http_pacing._clear_rate_limit_cooldowns_for_tests()


def run_extensionless_remote_image_header_filename(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path)

    image_bytes = b"\x89PNG\r\n\x1a\nremote-header-image"

    def _fake_ocr_path(_self, path: Path) -> str:  # noqa: ANN001
        if path.suffix.lower() == ".png":
            return "header-ocr@acme.example https://header.acme.example/poster"
        return ""

    monkeypatch.setattr(ArtifactQueueProcessor, "_ocr_image_path", _fake_ocr_path)

    class _DownloadHandler(SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return None

        def do_GET(self) -> None:  # noqa: N802
            if self.path.startswith("/opaque-download"):
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="header-briefing.png"',
                )
                self.send_header("Content-Length", str(len(image_bytes)))
                self.end_headers()
                self.wfile.write(image_bytes)
                return
            self.send_error(404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _DownloadHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        source_url = f"http://127.0.0.1:{server.server_address[1]}/opaque-download?id=42"
        con = sqlite3.connect(db_path)
        try:
            con.execute(
                """
                INSERT INTO artifact_queue
                    (engagement_id, source_url, artifact_type, discovered_from, status, metadata_json)
                VALUES
                    (1001, ?, 'document', 'engagement_seed', 'queued', '{}')
                """,
                (source_url,),
            )
            con.commit()
        finally:
            con.close()

        summary = ArtifactQueueProcessor(db_path, 1001).process()
        assert summary.processed == 1

        con = sqlite3.connect(db_path)
        try:
            artifact_row = con.execute(
                """
                SELECT status, local_path, artifact_type, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001 AND source_url=?
                """,
                (source_url,),
            ).fetchone()
            assert artifact_row is not None
            assert artifact_row[0] == "parsed"
            assert artifact_row[2] == "document"
            local_path = Path(str(artifact_row[1]))
            assert local_path.exists()
            assert local_path.suffix.lower() == ".png"
            metadata = json.loads(str(artifact_row[3] or "{}"))
            assert metadata["format"] == "png"
            assert metadata["content_type"] == "image/png"
            assert metadata["download_filename"].endswith("header-briefing.png")
            assert metadata["ocr_payload_count"] >= 1
        finally:
            con.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def run_extensionless_remote_avif_content_type(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path)

    image_bytes = b"\x00\x00\x00 ftypavif remote-avif-image"

    def _fake_ocr_path(_self, path: Path) -> str:  # noqa: ANN001
        if path.suffix.lower() == ".avif":
            return "remote-avif@acme.example https://remote-avif.acme.example/poster"
        return ""

    monkeypatch.setattr(ArtifactQueueProcessor, "_ocr_image_path", _fake_ocr_path)

    class _DownloadHandler(SimpleHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return None

        def do_GET(self) -> None:  # noqa: N802
            if self.path.startswith("/opaque-modern-image"):
                self.send_response(200)
                self.send_header("Content-Type", "image/avif")
                self.send_header("Content-Length", str(len(image_bytes)))
                self.end_headers()
                self.wfile.write(image_bytes)
                return
            self.send_error(404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _DownloadHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        source_url = f"http://127.0.0.1:{server.server_address[1]}/opaque-modern-image?id=42"
        con = sqlite3.connect(db_path)
        try:
            con.execute(
                """
                INSERT INTO artifact_queue
                    (engagement_id, source_url, artifact_type, discovered_from, status, metadata_json)
                VALUES
                    (1001, ?, 'document', 'engagement_seed', 'queued', '{}')
                """,
                (source_url,),
            )
            con.commit()
        finally:
            con.close()

        summary = ArtifactQueueProcessor(db_path, 1001).process()
        assert summary.processed == 1

        con = sqlite3.connect(db_path)
        try:
            artifact_row = con.execute(
                """
                SELECT status, local_path, artifact_type, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001 AND source_url=?
                """,
                (source_url,),
            ).fetchone()
            assert artifact_row is not None
            assert artifact_row[0] == "parsed"
            assert artifact_row[2] == "document"
            local_path = Path(str(artifact_row[1]))
            assert local_path.exists()
            assert local_path.suffix.lower() == ".avif"
            metadata = json.loads(str(artifact_row[3] or "{}"))
            assert metadata["format"] == "avif"
            assert metadata["content_type"] == "image/avif"
            assert metadata["download_filename"].endswith(".avif")
            assert metadata["ocr_payload_count"] >= 1

            seeds = {
                (row[0], row[1])
                for row in con.execute(
                    """
                    SELECT seed_value, seed_type
                    FROM engagement_seeds
                    WHERE engagement_id=1001
                    """
                ).fetchall()
            }
            assert ("remote-avif@acme.example", "email") in seeds
            assert ("https://remote-avif.acme.example/poster", "url") in seeds
        finally:
            con.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
