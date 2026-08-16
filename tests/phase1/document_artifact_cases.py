from __future__ import annotations

import json
import sqlite3
import threading
import time
import zipfile
from email.message import EmailMessage
from io import BytesIO
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    EmailPartExtractionJob,
    EmailPartPlanningEntry,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_epub_findings(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_epub"
    artifact_root.mkdir()
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json='["*.acme.example","+15551234567","security@acme.example","https://downloads.acme.example/app.apk"]',
        operator="delta-one",
    )

    epub_path = artifact_root / "engagement-brief.epub"
    with zipfile.ZipFile(epub_path, "w") as zf:
        zf.writestr("mimetype", "application/epub+zip")
        zf.writestr(
            "META-INF/container.xml",
            """
            <container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
              <rootfiles>
                <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
              </rootfiles>
            </container>
            """.strip(),
        )
        zf.writestr(
            "OEBPS/content.opf",
            """
            <package version="3.0" xmlns="http://www.idpf.org/2007/opf">
              <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
                <dc:title>Acme External Surface Brief</dc:title>
                <dc:creator>epub-meta@acme.example</dc:creator>
              </metadata>
            </package>
            """.strip(),
        )
        zf.writestr(
            "OEBPS/chapter1.xhtml",
            """
            <html xmlns="http://www.w3.org/1999/xhtml">
              <body>
                <p>epub-owner@acme.example</p>
                <p>https://books.acme.example/briefing</p>
                <p>https://acme-epub.firebaseio.com/public.json</p>
                <p>https://storage.googleapis.com/acme-epub-public/reports/index.html</p>
              </body>
            </html>
            """.strip(),
        )
        zf.writestr(
            "OEBPS/toc.ncx",
            """
            <ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">
              <docTitle><text>Acme</text></docTitle>
            </ncx>
            """.strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.discovered_seeds >= 4

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "epub-owner@acme.example" in emails
        assert "epub-meta@acme.example" in emails

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
        assert ("https://books.acme.example/briefing", "url") in seeds
        assert ("epub-owner@acme.example", "email") in seeds
        assert ("epub-meta@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "acme-epub") in cloud_assets
        assert ("gcs", "acme-epub-public") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[epub_path.resolve().as_posix()]["format"] == "epub"
    finally:
        con.close()


def run_mhtml_findings(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_mhtml"
    artifact_root.mkdir()
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json='["*.acme.example","+15551234567","security@acme.example","https://downloads.acme.example/app.apk"]',
        operator="delta-one",
    )

    mhtml_path = artifact_root / "engagement-brief.mhtml"
    message = EmailMessage()
    message["Subject"] = "Acme MHTML Brief"
    message["From"] = "mhtml-owner@acme.example"
    message["To"] = "ops@acme.example"
    message.set_type("multipart/related")
    message.add_alternative(
        """
        <html><body>
        analyst@mhtml.acme.example
        https://portal.mhtml.acme.example/report
        https://mhtml-firebase.firebaseio.com/public.json
        https://storage.googleapis.com/mhtml-gcs-public/reports/final.pdf
        </body></html>
        """.strip(),
        subtype="html",
    )
    message.add_attachment(
        """
        SUPABASE_URL=https://mhtmlbrief.supabase.co
        FIREBASE_DB=https://mhtml-alt.firebaseio.com
        """.strip().encode("utf-8"),
        maintype="text",
        subtype="plain",
        filename="config.txt",
    )
    mhtml_path.write_bytes(message.as_bytes())

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.discovered_seeds >= 4

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "mhtml-owner@acme.example" in emails
        assert "ops@acme.example" in emails
        assert "analyst@mhtml.acme.example" in emails

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
        assert ("https://portal.mhtml.acme.example/report", "url") in seeds
        assert ("mhtml-owner@acme.example", "email") in seeds
        assert ("ops@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "mhtml-firebase") in cloud_assets
        assert ("firebase", "mhtml-alt") in cloud_assets
        assert ("gcs", "mhtml-gcs-public") in cloud_assets
        assert ("supabase", "mhtmlbrief") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[mhtml_path.resolve().as_posix()]["format"] == "mhtml"
    finally:
        con.close()


def run_eml_bodies_and_nested_attachments(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_mail"
    artifact_root.mkdir()
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json='["*.acme.example","+15551234567","security@acme.example","https://downloads.acme.example/app.apk"]',
        operator="delta-one",
    )

    eml_path = artifact_root / "engagement-briefing.eml"

    attachment_zip = BytesIO()
    with zipfile.ZipFile(attachment_zip, "w") as zf:
        zf.writestr(
            "config/app.env",
            """
            SUPABASE_URL=https://mailbrief.supabase.co
            SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1haWxicmllZiIsInJvbGUiOiJhbm9uIn0.signature789
            FIREBASE_DB=https://mail-firebase.firebaseio.com
            PUBLIC_BUCKET=s3://acme-mail-bucket/reports/latest.pdf
            CONTACT=attachment-owner@acme.example
            """.strip(),
        )

    docx_bytes = BytesIO()
    with zipfile.ZipFile(docx_bytes, "w") as zf:
        zf.writestr(
            "word/document.xml",
            """
            <w:document>
              <w:body>
                <w:p>docx-owner@acme.example https://docx.acme.example/report</w:p>
              </w:body>
            </w:document>
            """.strip(),
        )
        zf.writestr(
            "docProps/core.xml",
            """
            <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                               xmlns:dc="http://purl.org/dc/elements/1.1/">
              <dc:creator>docx-owner@acme.example</dc:creator>
              <dc:title>Mail Attachment Briefing</dc:title>
            </cp:coreProperties>
            """.strip(),
        )

    message = EmailMessage()
    message["Subject"] = "Executive Briefing"
    message["From"] = "Analyst <analyst@acme.example>"
    message["To"] = "Security Team <security@acme.example>"
    message["Cc"] = "Lead <lead@acme.example>"
    message.set_content(
        "Contact mail-owner@acme.example and review https://mail.acme.example/brief"
    )
    message.add_alternative(
        "<html><body>See https://htmlmail.acme.example/panel for updates.</body></html>",
        subtype="html",
    )
    message.add_attachment(
        attachment_zip.getvalue(),
        maintype="application",
        subtype="zip",
        filename="evidence.zip",
    )
    message.add_attachment(
        docx_bytes.getvalue(),
        maintype="application",
        subtype="vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename="briefing.docx",
    )
    eml_path.write_bytes(message.as_bytes())

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1
    assert summary.discovered_seeds >= 8

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "analyst@acme.example" in emails
        assert "security@acme.example" in emails
        assert "lead@acme.example" in emails
        assert "mail-owner@acme.example" in emails
        assert "attachment-owner@acme.example" in emails
        assert "docx-owner@acme.example" in emails

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
        assert ("https://mail.acme.example/brief", "url") in seeds
        assert ("https://htmlmail.acme.example/panel", "url") in seeds
        assert ("https://docx.acme.example/report", "url") in seeds
        assert ("mail-owner@acme.example", "email") in seeds
        assert ("attachment-owner@acme.example", "email") in seeds
        assert ("docx-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-mail-bucket") in cloud_assets
        assert ("firebase", "mail-firebase") in cloud_assets
        assert ("supabase", "mailbrief") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[eml_path.resolve().as_posix()]["format"] == "eml"
        assert artifact_meta[eml_path.resolve().as_posix()]["metadata_payload_count"] >= 2
    finally:
        con.close()


def run_email_attachment_parts_parallel_order(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    db_path = tmp_path / "engagement.db"
    eml_path = tmp_path / "parallel-message.eml"

    message = EmailMessage()
    message["Subject"] = "Parallel attachments"
    message["From"] = "parallel-owner@acme.example"
    message["To"] = "ops@acme.example"
    message.make_mixed()
    for index in range(1, 4):
        message.add_attachment(
            f"attachment-{index}".encode("utf-8"),
            maintype="application",
            subtype="octet-stream",
            filename=f"attachment-{index}.bin",
        )
    eml_path.write_bytes(message.as_bytes())

    delays = {
        "attachment-1.bin": 0.05,
        "attachment-2.bin": 0.01,
        "attachment-3.bin": 0.03,
    }
    payload_texts = {
        "attachment-1.bin": "attachment-one@acme.example",
        "attachment-2.bin": "attachment-two@acme.example",
        "attachment-3.bin": "attachment-three@acme.example",
    }
    active = 0
    peak = 0
    lock = threading.Lock()

    def _fake_extract_email_part_job(
        _self,
        job,
    ) -> list[tuple[str, str, str]]:  # noqa: ANN001
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[job.member_name])
            return [(job.source_file, job.member_name, payload_texts[job.member_name])]
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_email_part_job",
        _fake_extract_email_part_job,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=2)
    payloads = processor._extract_email_message_payloads(
        eml_path.read_bytes(),
        str(eml_path),
        eml_path.name,
        depth=0,
    )

    assert peak == 2
    assert payloads[0][0] == str(eml_path)
    assert payloads[0][1] == f"{eml_path.name}#message-meta"
    assert "subject=Parallel attachments" in payloads[0][2]
    assert "from=parallel-owner@acme.example" in payloads[0][2]
    assert payloads[1:] == [
        (str(eml_path), "attachment-1.bin", "attachment-one@acme.example"),
        (str(eml_path), "attachment-2.bin", "attachment-two@acme.example"),
        (str(eml_path), "attachment-3.bin", "attachment-three@acme.example"),
    ]


def run_email_part_planning_parallel_order(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    db_path = tmp_path / "engagement.db"
    source_file = str(tmp_path / "planned-message.eml")
    member_name = "planned-message.eml"
    delays = {
        1: 0.05,
        2: 0.01,
        3: 0.03,
        4: 0.02,
        5: 0.04,
    }
    active = 0
    peak = 0
    entered = 0
    lock = threading.Lock()
    gate = threading.Event()
    original_entry = ArtifactQueueProcessor._email_message_part_entry

    class _FakeNestedMessage:
        def __init__(self, label: str) -> None:
            self.label = label

        def as_bytes(self, policy=None) -> bytes:  # noqa: ANN001
            del policy
            return f"payload-{self.label}".encode("utf-8")

    class _FakePart:
        def __init__(
            self,
            *,
            content_type: str,
            filename: str = "",
            payload_bytes: bytes | None = None,
            raw_payload: str | None = None,
            nested_messages=None,  # noqa: ANN001
            charset: str = "utf-8",
        ) -> None:
            self._content_type = content_type
            self._filename = filename
            self._payload_bytes = payload_bytes
            self._raw_payload = raw_payload
            self._nested_messages = list(nested_messages or [])
            self._charset = charset

        def get_content_type(self) -> str:
            return self._content_type

        def get_filename(self) -> str:
            return self._filename

        def get_payload(self, decode: bool = False):  # noqa: ANN201
            if self._content_type == "message/rfc822":
                return None if decode else list(self._nested_messages)
            if decode:
                return self._payload_bytes
            if self._raw_payload is not None:
                return self._raw_payload
            return self._payload_bytes

        def get_content_charset(self) -> str:
            return self._charset

    def _tracking_entry(
        self,
        part_job,
        *,
        source_file: str,
        member_name: str,
        depth: int,
    ):  # noqa: ANN001
        nonlocal active, peak, entered
        part_index, _part = part_job
        with lock:
            active += 1
            peak = max(peak, active)
            entered += 1
            current_entered = entered
            if entered >= 4:
                gate.set()
        try:
            if current_entered <= 4:
                assert gate.wait(timeout=1.0)
            time.sleep(delays[part_index])
            return original_entry(
                self,
                part_job,
                source_file=source_file,
                member_name=member_name,
                depth=depth,
            )
        finally:
            with lock:
                active -= 1

    def _fake_extract_email_part_job(
        _self,
        job,
    ) -> list[tuple[str, str, str]]:  # noqa: ANN001
        if job.member_name == "attachment-2.bin":
            assert job.payload_bytes == b"attachment-two"
            assert job.nested_messages == []
            return [(job.source_file, job.member_name, "attachment-two@acme.example")]
        if job.member_name == "forwarded.eml":
            assert job.payload_bytes is None
            assert job.nested_messages == [("forwarded.eml", b"payload-forward-1")]
            return [(job.source_file, job.member_name, "forwarded@acme.example")]
        if job.member_name == "attachment-5.bin":
            assert job.payload_bytes == b"attachment-five"
            assert job.nested_messages == []
            return [(job.source_file, job.member_name, "attachment-five@acme.example")]
        raise AssertionError(f"unexpected job {job.member_name}")

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_email_message_part_entry",
        _tracking_entry,
    )
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_email_part_job",
        _fake_extract_email_part_job,
    )

    leaf_parts = [
        _FakePart(content_type="text/plain", payload_bytes=b"plain-one@acme.example"),
        _FakePart(
            content_type="application/octet-stream",
            filename="attachment-2.bin",
            payload_bytes=b"attachment-two",
        ),
        _FakePart(
            content_type="message/rfc822",
            filename="forwarded.eml",
            nested_messages=[_FakeNestedMessage("forward-1")],
        ),
        _FakePart(content_type="text/html", payload_bytes=b"<p>html-four@acme.example</p>"),
        _FakePart(
            content_type="application/octet-stream",
            filename="attachment-5.bin",
            payload_bytes=b"attachment-five",
        ),
    ]

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=8)
    payloads = processor._extract_email_message_part_payloads(
        leaf_parts,
        source_file=source_file,
        member_name=member_name,
        depth=1,
    )

    assert peak >= 4
    assert payloads == [
        (source_file, f"{member_name}.part-1.txt", "plain-one@acme.example"),
        (source_file, "attachment-2.bin", "attachment-two@acme.example"),
        (source_file, "forwarded.eml", "forwarded@acme.example"),
        (source_file, f"{member_name}.part-4.html", "<p>html-four@acme.example</p>"),
        (source_file, "attachment-5.bin", "attachment-five@acme.example"),
    ]


def run_nested_email_message_job_planning_parallel_order(
    tmp_path: Path,
    monkeypatch,
) -> None:  # noqa: ANN001
    db_path = tmp_path / "engagement.db"
    source_file = str(tmp_path / "outer-message.eml")
    member_name = "outer-message.eml"
    expected_names = [
        f"{member_name}.attached-1-1.eml",
        f"{member_name}.attached-1-2.eml",
        f"{member_name}.attached-1-3.eml",
        f"{member_name}.attached-1-4.eml",
        f"{member_name}.attached-1-5.eml",
    ]
    delays = {
        expected_names[0]: 0.05,
        expected_names[1]: 0.01,
        expected_names[2]: 0.03,
        expected_names[3]: 0.02,
        expected_names[4]: 0.04,
        f"{member_name}.attached-1-6.eml": 0.01,
    }
    active = 0
    peak = 0
    lock = threading.Lock()
    original_job = ArtifactQueueProcessor._nested_email_message_job

    class _FakeNestedMessage:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def as_bytes(self, policy=None) -> bytes:  # noqa: ANN001
            del policy
            return self._payload

    class _FakePart:
        def __init__(self, nested_messages) -> None:  # noqa: ANN001
            self._nested_messages = list(nested_messages)

        def get_content_type(self) -> str:
            return "message/rfc822"

        def get_filename(self) -> str:
            return ""

        def get_payload(self, decode: bool = False):  # noqa: ANN201
            return None if decode else list(self._nested_messages)

    def _tracking_job(nested_job):  # noqa: ANN001
        nonlocal active, peak
        nested_name, _nested_bytes = nested_job
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[nested_name])
            return original_job(nested_job)
        finally:
            with lock:
                active -= 1

    def _fake_extract_email_part_job(
        _self,
        job,
    ) -> list[tuple[str, str, str]]:  # noqa: ANN001
        assert job.member_name == f"{member_name}.attached-1.eml"
        assert [nested_name for nested_name, _nested_bytes in job.nested_messages] == expected_names
        return [
            (job.source_file, nested_name, nested_name)
            for nested_name, _nested_bytes in job.nested_messages
        ]

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_nested_email_message_job",
        staticmethod(_tracking_job),
    )
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_email_part_job",
        _fake_extract_email_part_job,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=8)
    payloads = processor._extract_email_message_part_payloads(
        [
            _FakePart(
                [
                    _FakeNestedMessage(b"nested-1"),
                    _FakeNestedMessage(b"nested-2"),
                    _FakeNestedMessage(b"nested-3"),
                    _FakeNestedMessage(b"nested-4"),
                    _FakeNestedMessage(b"nested-5"),
                    _FakeNestedMessage(b""),
                ]
            )
        ],
        source_file=source_file,
        member_name=member_name,
        depth=1,
    )

    assert peak == 4
    assert payloads == [
        (source_file, expected_names[0], expected_names[0]),
        (source_file, expected_names[1], expected_names[1]),
        (source_file, expected_names[2], expected_names[2]),
        (source_file, expected_names[3], expected_names[3]),
        (source_file, expected_names[4], expected_names[4]),
    ]


def run_email_part_payload_entries_parallel_order(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    db_path = tmp_path / "engagement.db"
    source_file = str(tmp_path / "part-entry-message.eml")
    member_name = "part-entry-message.eml"
    active = 0
    peak = 0
    entered = 0
    lock = threading.Lock()
    gate = threading.Event()
    delays = {0: 0.05, 1: 0.01, 2: 0.03}
    original_entry = ArtifactQueueProcessor._artifact_payload_tuple_batch_entries

    def _tracking_entry(payload_batch):  # noqa: ANN001
        nonlocal active, peak, entered
        batch_index, _batch = payload_batch
        with lock:
            active += 1
            peak = max(peak, active)
            entered += 1
            current_entered = entered
            if entered >= 3:
                gate.set()
        try:
            if current_entered <= 3:
                assert gate.wait(timeout=1.0)
            time.sleep(delays[batch_index])
            return original_entry(payload_batch)
        finally:
            with lock:
                active -= 1

    def _fake_email_message_part_entry(
        _self,
        part_job,
        *,
        source_file: str,
        member_name: str,
        depth: int,
    ) -> EmailPartPlanningEntry:  # noqa: ANN001
        part_index, _part = part_job
        if part_index == 1:
            return EmailPartPlanningEntry(
                payloads=[
                    (source_file, f"{member_name}.part-1.txt", "direct"),
                    ("", "ignored", "ignored"),
                ]
            )
        return EmailPartPlanningEntry(
            extraction_job=EmailPartExtractionJob(
                source_file=source_file,
                member_name=f"{member_name}.part-{part_index}.bin",
                depth=depth,
                payload_bytes=f"part-{part_index}".encode("utf-8"),
            )
        )

    def _fake_extract_email_part_job(
        _self,
        job: EmailPartExtractionJob,
    ) -> list[tuple[str, str, str]]:
        return [
            (job.source_file, job.member_name, job.payload_bytes.decode("utf-8")),
            (job.source_file, f"{job.member_name}#empty", ""),
        ]

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_artifact_payload_tuple_batch_entries",
        staticmethod(_tracking_entry),
    )
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_email_message_part_entry",
        _fake_email_message_part_entry,
    )
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_email_part_job",
        _fake_extract_email_part_job,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    payloads = processor._extract_email_message_part_payloads(
        [object(), object(), object()],
        source_file=source_file,
        member_name=member_name,
        depth=1,
    )

    assert peak == 3
    assert payloads == [
        (source_file, f"{member_name}.part-1.txt", "direct"),
        (source_file, f"{member_name}.part-2.bin", "part-2"),
        (source_file, f"{member_name}.part-3.bin", "part-3"),
    ]


def run_nested_email_part_messages_parallel_order(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    db_path = tmp_path / "engagement.db"
    source_file = str(tmp_path / "outer-message.eml")
    delays = {
        "nested-1.eml": 0.05,
        "nested-2.eml": 0.01,
        "nested-3.eml": 0.03,
    }
    payload_texts = {
        "nested-1.eml": "nested-one@acme.example",
        "nested-2.eml": "nested-two@acme.example",
        "nested-3.eml": "nested-three@acme.example",
    }
    active = 0
    peak = 0
    lock = threading.Lock()

    def _fake_extract_email_message_payloads(
        _self,
        nested_bytes: bytes,
        nested_source_file: str,
        nested_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:  # noqa: ANN001
        assert nested_source_file == source_file
        assert nested_bytes == f"payload-{nested_name}".encode("utf-8")
        assert depth == 2
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[nested_name])
            return [(nested_source_file, nested_name, payload_texts[nested_name])]
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_email_message_payloads",
        _fake_extract_email_message_payloads,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    payloads = processor._extract_email_part_job(
        EmailPartExtractionJob(
            source_file=source_file,
            member_name="attached.eml",
            depth=1,
            nested_messages=[
                ("nested-1.eml", b"payload-nested-1.eml"),
                ("nested-2.eml", b"payload-nested-2.eml"),
                ("nested-3.eml", b"payload-nested-3.eml"),
            ],
        )
    )

    assert peak == 3
    assert payloads == [
        (source_file, "nested-1.eml", "nested-one@acme.example"),
        (source_file, "nested-2.eml", "nested-two@acme.example"),
        (source_file, "nested-3.eml", "nested-three@acme.example"),
    ]


def run_nested_email_payload_entries_parallel_order(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    db_path = tmp_path / "engagement.db"
    source_file = str(tmp_path / "outer-message-payload-entries.eml")
    nested_messages = [
        ("nested-1.eml", b"payload-nested-1.eml"),
        ("nested-2.eml", b"payload-nested-2.eml"),
        ("nested-3.eml", b"payload-nested-3.eml"),
    ]
    active = 0
    peak = 0
    entered = 0
    lock = threading.Lock()
    gate = threading.Event()
    delays = {0: 0.05, 1: 0.01, 2: 0.03}
    original_entry = ArtifactQueueProcessor._artifact_payload_tuple_batch_entries

    def _tracking_entry(payload_batch):  # noqa: ANN001
        nonlocal active, peak, entered
        batch_index, _batch = payload_batch
        with lock:
            active += 1
            peak = max(peak, active)
            entered += 1
            current_entered = entered
            if entered >= 3:
                gate.set()
        try:
            if current_entered <= 3:
                assert gate.wait(timeout=1.0)
            time.sleep(delays[batch_index])
            return original_entry(payload_batch)
        finally:
            with lock:
                active -= 1

    def _fake_extract_email_message_payloads(
        _self,
        nested_bytes: bytes,
        nested_source_file: str,
        nested_name: str,
        *,
        depth: int,
    ) -> list[tuple[str, str, str]]:  # noqa: ANN001
        assert nested_source_file == source_file
        assert nested_bytes == f"payload-{nested_name}".encode("utf-8")
        assert depth == 2
        return [
            (nested_source_file, nested_name, nested_name),
            (nested_source_file, f"{nested_name}#empty", ""),
            ("", "ignored", "ignored"),
        ]

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_artifact_payload_tuple_batch_entries",
        staticmethod(_tracking_entry),
    )
    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_extract_email_message_payloads",
        _fake_extract_email_message_payloads,
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    payloads = processor._extract_email_part_job(
        EmailPartExtractionJob(
            source_file=source_file,
            member_name="attached.eml",
            depth=1,
            nested_messages=nested_messages,
        )
    )

    assert peak == 3
    assert payloads == [
        (source_file, "nested-1.eml", "nested-1.eml"),
        (source_file, "nested-2.eml", "nested-2.eml"),
        (source_file, "nested-3.eml", "nested-3.eml"),
    ]


def run_email_part_decoding_parallel_charset_order(monkeypatch) -> None:  # noqa: ANN001
    class _FakePart:
        def get_content_charset(self) -> str:
            return "x-invalid-charset"

    active = 0
    peak = 0
    lock = threading.Lock()
    delays = {
        "x-invalid-charset": 0.05,
        "utf-8": 0.01,
        "latin-1": 0.03,
    }
    decoded = {
        "x-invalid-charset": None,
        "utf-8": "owner@acme.example",
        "latin-1": "late-latin@acme.example",
    }

    def _fake_decode_email_part_entry(entry: tuple[str, bytes]) -> str | None:
        encoding, bounded = entry
        assert bounded == b"mail-bytes"
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[encoding])
            return decoded[encoding]
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_decode_email_part_entry",
        staticmethod(_fake_decode_email_part_entry),
    )

    text = ArtifactQueueProcessor._decode_email_part_text(_FakePart(), b"mail-bytes")

    assert peak == 3
    assert text == "owner@acme.example"
