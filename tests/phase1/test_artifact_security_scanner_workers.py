from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_security_scanner_config_candidates_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        sonar.host.url=sonar.acme.example
        sonar.links.homepage=https://sonar-home.acme.example/project
        repositories=[
          "ghcr.io/acme/trivy-db",
        ]
        server: trivy-control.acme.example
        endpoint=https://${tenant}.acme.example/template
        """
    ).strip()
    observed_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_security_scanner_config_candidate_entry":
            observed_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._security_scanner_config_structured_payload_text(
        payload,
        source_hint="sonar-project.properties",
    )

    assert observed_batches == [
        [
            "sonar.acme.example",
            "https://sonar-home.acme.example/project",
            "ghcr.io/acme/trivy-db",
            "trivy-control.acme.example",
            "https://${tenant}.acme.example/template",
        ]
    ]
    assert result.splitlines() == [
        "https://sonar.acme.example",
        "https://sonar-home.acme.example/project",
        "https://ghcr.io/acme/trivy-db",
        "https://trivy-control.acme.example",
    ]
