from __future__ import annotations

import threading
import time
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_github_actions_uses_children_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    document = {
        "one": {"uses": "actions/setup-python@v5"},
        "two": {"steps": [{"uses": "docker://ghcr.io/acme/helper:latest"}]},
        "three": {"uses": "https://github.com/acme/reusable-action@v1"},
        "four": {
            "uses": "./local",
            "nested": {"uses": "acme/shared/.github/workflows/deploy.yml@v2"},
        },
    }
    original_child = ArtifactQueueProcessor._yaml_github_actions_uses_child_candidate_values
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_child_values(
        self: ArtifactQueueProcessor,
        child_job: tuple[object, object, object],
    ) -> list[str]:
        nonlocal active, peak
        tracks_top_level = child_job[0] in {"one", "two", "three", "four"}
        if tracks_top_level:
            with lock:
                active += 1
                peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_child(self, child_job)
        finally:
            if tracks_top_level:
                with lock:
                    active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_yaml_github_actions_uses_child_candidate_values",
        _tracking_child_values,
    )

    assert processor._yaml_github_actions_uses_candidates(document) == [
        "https://github.com/actions/setup-python",
        "github-action://actions/setup-python",
        "https://ghcr.io/acme/helper",
        "https://github.com/acme/reusable-action",
        "https://github.com/acme/shared",
        "github-action://acme/shared/.github/workflows/deploy.yml",
    ]
    assert peak == 4


def test_ci_repository_walkers_use_ordered_worker_path_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    observed_workers: list[str] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        observed_workers.append(getattr(worker, "__name__", ""))
        return original_batch(
            self,
            list(items),
            worker,
            default_factory=default_factory,
        )

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    azure = {
        "resources": {
            "repositories": [
                {"type": "github", "name": "acme/azure-templates"},
                {"type": "bitbucket", "name": "acme/azure-tools"},
                {"url": "https://dev.azure.com/acme/platform/_git/infra-tools"},
            ]
        }
    }
    bitbucket = {
        "definitions": {
            "repositories": {
                "shared": {"url": "https://bitbucket.org/acme/pipeline-templates.git"},
                "infra": "acme/infra-scripts",
            }
        }
    }
    gitlab = {
        "include": [
            {"project": "acme/ci-templates"},
            {"remote": "https://gitlab.com/acme/remote-pipelines/raw/main/deploy.yml"},
            {"component": "gitlab.com/acme/components/deploy@1.0.0"},
        ]
    }

    assert processor._yaml_azure_pipelines_repository_candidates(azure) == [
        "https://github.com/acme/azure-templates",
        "https://bitbucket.org/acme/azure-tools",
        "https://dev.azure.com/acme/platform/_git/infra-tools",
    ]
    assert processor._yaml_bitbucket_pipelines_repository_candidates(bitbucket) == [
        "https://bitbucket.org/acme/pipeline-templates",
        "https://bitbucket.org/acme/infra-scripts",
    ]
    assert processor._yaml_gitlab_ci_include_repository_candidates(gitlab) == [
        "https://gitlab.com/acme/ci-templates",
        "https://gitlab.com/acme/remote-pipelines/raw/main/deploy.yml",
        "https://gitlab.com/acme/components",
    ]
    assert {
        "_yaml_azure_pipeline_repository_entry_candidates",
        "_yaml_bitbucket_repository_child_candidate_values",
        "_yaml_gitlab_ci_include_child_candidate_values",
    }.issubset(set(observed_workers))


def test_ci_container_walkers_use_ordered_worker_path_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    observed_workers: list[str] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        observed_workers.append(getattr(worker, "__name__", ""))
        return original_batch(
            self,
            list(items),
            worker,
            default_factory=default_factory,
        )

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    circleci = {
        "executors": {"release": {"docker": [{"image": "ghcr.io/acme/circle-exec:1"}]}},
        "jobs": {"deploy": {"docker": [{"image": "registry.acme.example/ci/deploy:2"}]}},
    }
    azure = {
        "resources": {"containers": [{"container": "build", "image": "ghcr.io/acme/azdo-build:1"}]},
        "jobs": [{"job": "deploy", "container": "mcr.microsoft.com/azure-cli:latest"}],
    }
    bitbucket = {
        "image": "ghcr.io/acme/bitbucket-runner:latest",
        "definitions": {"services": {"scanner": {"image": "registry.gitlab.com/acme/scanner:2"}}},
    }
    gitlab = {
        "default": {
            "services": [{"name": "registry.gitlab.com/acme/postgres:14"}]
        },
        "deploy": {"services": ["registry.gitlab.com/acme/redis:7"]},
    }

    assert processor._yaml_circleci_container_candidates(circleci) == [
        "https://ghcr.io/acme/circle-exec",
        "https://registry.acme.example/ci/deploy",
    ]
    assert processor._yaml_azure_pipelines_container_candidates(azure) == [
        "https://ghcr.io/acme/azdo-build",
        "https://mcr.microsoft.com/azure-cli",
    ]
    assert processor._yaml_bitbucket_pipelines_container_candidates(bitbucket) == [
        "https://ghcr.io/acme/bitbucket-runner",
        "https://registry.gitlab.com/acme/scanner",
    ]
    assert processor._yaml_gitlab_ci_service_container_candidates(gitlab) == [
        "https://registry.gitlab.com/acme/postgres",
        "https://registry.gitlab.com/acme/redis",
    ]
    assert {
        "_yaml_circleci_container_child_candidate_values",
        "_yaml_azure_pipeline_container_resource_entry_candidates",
        "_yaml_azure_pipelines_container_child_values",
        "_yaml_bitbucket_container_child_candidate_values",
        "_yaml_gitlab_ci_service_container_child_values",
    }.issubset(set(observed_workers))
