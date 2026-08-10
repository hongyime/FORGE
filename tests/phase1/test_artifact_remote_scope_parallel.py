from __future__ import annotations

from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactDownloadRequest,
    ArtifactDownloadResult,
    ArtifactQueueProcessor,
)


def test_parallel_remote_artifact_download_preserves_scope_skip_attribution(
    tmp_path: Path,
    monkeypatch,
) -> None:
    requests = [
        ArtifactDownloadRequest(
            artifact_id=10,
            source_url="https://blocked.example/app.apk",
            artifact_type="apk",
        ),
        ArtifactDownloadRequest(
            artifact_id=11,
            source_url="https://allowed.example/fail.apk",
            artifact_type="apk",
        ),
        ArtifactDownloadRequest(
            artifact_id=12,
            source_url="https://allowed.example/ok.apk",
            artifact_type="apk",
        ),
    ]
    denied: list[tuple[str, str]] = []

    def _fake_download(
        self: ArtifactQueueProcessor, request: ArtifactDownloadRequest
    ) -> ArtifactDownloadResult:
        del self
        if request.source_url.endswith("/fail.apk"):
            raise RuntimeError("synthetic downloader failure")
        return ArtifactDownloadResult(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=request.artifact_type,
            path=tmp_path / "ok.apk",
        )

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_download_remote_artifact_request",
        _fake_download,
    )
    processor = ArtifactQueueProcessor(
        tmp_path / "engagement.db",
        1001,
        max_workers=2,
        remote_url_scope_checker=lambda url: "blocked.example" not in url,
        remote_scope_denied_callback=lambda request, reason: denied.append(
            (request.source_url, reason)
        ),
    )

    results = processor._download_remote_artifacts(requests)
    by_url = {result.source_url: result for result in results}

    assert denied == [("https://blocked.example/app.apk", "scope_manifest_denied_remote_artifact")]
    assert by_url["https://blocked.example/app.apk"].artifact_id == 10
    assert by_url["https://blocked.example/app.apk"].error == (
        "scope_manifest_denied_remote_artifact"
    )
    assert by_url["https://allowed.example/fail.apk"].artifact_id == 11
    assert by_url["https://allowed.example/fail.apk"].error is not None
    assert "RuntimeError" in by_url["https://allowed.example/fail.apk"].error
    assert by_url["https://allowed.example/ok.apk"].artifact_id == 12
    assert by_url["https://allowed.example/ok.apk"].error is None
