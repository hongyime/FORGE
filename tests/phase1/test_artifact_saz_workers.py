from __future__ import annotations

import threading
import time
import zipfile
from io import BytesIO
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_saz_raw_session_member_classification_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    archive = BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(
            "raw/0002_c.txt",
            "\r\n".join(
                [
                    "GET https://two.acme.example/session HTTP/1.1",
                    "Host: two.acme.example",
                    "",
                    "",
                ]
            ),
        )
        zf.writestr(
            "raw/0001_c.txt",
            "\r\n".join(
                [
                    "GET https://one.acme.example/session HTTP/1.1",
                    "Host: one.acme.example",
                    "",
                    "",
                ]
            ),
        )
        zf.writestr(
            "raw/0002_s.txt",
            "\r\n".join(["HTTP/1.1 302 Found", "Location: /next?token=hidden&view=public", "", ""]),
        )
        zf.writestr(
            "raw/0001_s.txt",
            "\r\n".join(["HTTP/1.1 302 Found", "Location: /home?api_key=hidden&view=public", "", ""]),
        )

    original_entry = ArtifactQueueProcessor._saz_raw_session_member_entry
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_member_entry(member: zipfile.ZipInfo) -> tuple[str, str, str] | None:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_entry(member)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_saz_raw_session_member_entry",
        staticmethod(_tracking_member_entry),
    )

    with zipfile.ZipFile(BytesIO(archive.getvalue())) as zf:
        payloads = processor._extract_saz_session_pairing_payloads(
            zf,
            "capture.saz",
        )

    assert peak == 4
    assert payloads == [
        (
            "capture.saz",
            "raw/0001_c+s.txt#saz-session-pair",
            "\n".join(
                [
                    "request.member=raw/0001_c.txt",
                    "response.member=raw/0001_s.txt",
                    "https://one.acme.example/home?view=public",
                ]
            ),
        ),
        (
            "capture.saz",
            "raw/0002_c+s.txt#saz-session-pair",
            "\n".join(
                [
                    "request.member=raw/0002_c.txt",
                    "response.member=raw/0002_s.txt",
                    "https://two.acme.example/next?view=public",
                ]
            ),
        ),
    ]
