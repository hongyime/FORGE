from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_static_hosting_control_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        # Netlify/Pages redirects are passive hosting-control metadata.
        /api/* https://api.acme.example/:splat?token=hidden&view=ops 200
        /admin/* /dashboard/:splat 301
        <https://cdn.acme.example/app.css?api_key=hidden&view=public>; rel=preload
        /firebase/* https://redirects-firebase.firebaseio.com/:splat 200
        """
    ).strip()
    observed_line_labels: list[str] = []
    observed_url_candidates: list[str] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_static_hosting_control_line_candidate_values":
            observed_line_labels.extend(str(item[0]) for item in materialized)
        if getattr(worker, "__name__", "") == "_static_hosting_control_url_candidate_entry":
            observed_url_candidates.extend(str(item[0]) for item in materialized)
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._static_hosting_control_text_structured_payload_text(
        payload,
        source_hint="_redirects",
        base_url="https://acme.example/_redirects",
    )

    assert observed_line_labels == ["static-hosting-redirects"] * 5
    assert observed_url_candidates == [
        "/api/*",
        "https://api.acme.example/:splat?token=hidden&view=ops",
        "/admin/*",
        "/dashboard/:splat",
        "https://cdn.acme.example/app.css?api_key=hidden&view=public",
        "rel=preload",
        "/firebase/*",
        "https://redirects-firebase.firebaseio.com/:splat",
    ]
    assert result.splitlines() == [
        "https://acme.example/api/*",
        "https://api.acme.example/:splat?view=ops",
        "https://acme.example/admin/*",
        "https://acme.example/dashboard/:splat",
        "https://cdn.acme.example/app.css?view=public",
        "https://acme.example/firebase/*",
        "https://redirects-firebase.firebaseio.com/:splat",
    ]
