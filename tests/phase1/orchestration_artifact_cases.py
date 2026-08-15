from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any

from forge.engagement_orchestrator import ArtifactQueueProcessor, _artifact_format_label


def run_nomad_job_orchestration_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        job "api" {
          group "web" {
            service {
              tags = ["traefik.http.routers.api.rule=Host(`nomad-edge.acme.example`)"]
              check {
                address = "nomad-check.acme.example:8080"
              }
            }
            task "api" {
              env {
                endpoint = "nomad-api.acme.example/v1"
                templated = "https://${tenant}.acme.example/api"
              }
            }
          }
        }
        """
    ).strip()
    observed_line_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_edge_proxy_line_url_candidates":
            observed_line_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    assert _artifact_format_label("jobs/api.hcl") != "nomad-job"
    assert _artifact_format_label("nomad/api.hcl") == "nomad-job"
    assert _artifact_format_label("nomad/jobs/api.nomad.hcl") == "nomad-job"
    assert (
        processor._orchestration_structured_payload_text(
            payload,
            source_hint="notes/app.hcl",
        )
        == ""
    )
    assert (
        processor._orchestration_structured_payload_text(
            payload,
            source_hint="jobs/api.hcl",
        )
        == ""
    )

    result = processor._orchestration_structured_payload_text(
        payload,
        source_hint="nomad/jobs/api.nomad.hcl",
    )

    assert observed_line_batches[0] == payload.splitlines()
    assert result.splitlines() == [
        "http://nomad-edge.acme.example",
        "http://nomad-check.acme.example:8080",
        "http://nomad-api.acme.example/v1",
    ]
