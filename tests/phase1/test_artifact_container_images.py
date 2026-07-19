from __future__ import annotations

import threading
import time
from textwrap import dedent

from forge.engagement_orchestrator import _extract_artifact_container_image_urls


def test_artifact_container_image_lines_use_bounded_workers_and_preserve_order(
    monkeypatch,
) -> None:
    delays = {
        "FROM --platform=linux/amd64 docker.io/library/node:20 AS builder": 0.05,
        "image: ghcr.io/acme/api:latest": 0.05,
        "repository: quay.io/acme/worker": 0.05,
        "image: ghcr.io/acme/api:stable": 0.05,
        "image: registry.acme.example/team/collector@sha256:abcdef": 0.05,
    }
    active = 0
    peak = 0
    lock = threading.Lock()

    def _fake_artifact_container_image_line_candidates(raw_line: str) -> list[str]:
        assert raw_line in delays
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[raw_line])
            if raw_line.startswith("FROM"):
                return ["https://hub.docker.com/r/library/node"]
            if raw_line == "image: ghcr.io/acme/api:latest":
                return ["https://ghcr.io/acme/api"]
            if raw_line == "repository: quay.io/acme/worker":
                return ["https://quay.io/repository/acme/worker"]
            if raw_line == "image: ghcr.io/acme/api:stable":
                return ["https://ghcr.io/acme/api"]
            if raw_line.startswith("image: registry.acme.example"):
                return ["https://registry.acme.example/team/collector"]
            return []
        finally:
            with lock:
                active -= 1

    monkeypatch.setenv("FORGE_STATIC_ARTIFACT_MAX_WORKERS", "4")
    monkeypatch.setattr(
        "forge.engagement_orchestrator._artifact_container_image_line_candidates",
        _fake_artifact_container_image_line_candidates,
    )

    urls = _extract_artifact_container_image_urls("\n".join(delays))

    assert peak == 4
    assert urls == [
        "https://hub.docker.com/r/library/node",
        "https://ghcr.io/acme/api",
        "https://quay.io/repository/acme/worker",
        "https://registry.acme.example/team/collector",
    ]


def test_artifact_container_image_urls_promote_helm_oci_repository_url_lines() -> None:
    text = dedent(
        """
        repositories:
          - name: acme
            url: oci://ghcr.io/acme/helm-charts
          - name: bitnami
            repoURL: oci://registry-1.docker.io/bitnamicharts
        dependencies:
          - name: api
            repository: oci://registry.acme.example/platform/charts
          - name: ignored
            url: https://charts.acme.example/stable
        """
    )

    assert _extract_artifact_container_image_urls(text) == [
        "https://ghcr.io/acme/helm-charts",
        "https://hub.docker.com/r/library/bitnamicharts",
        "https://registry.acme.example/platform/charts",
    ]


def test_artifact_container_image_urls_promote_docker_bake_tags_and_cache_refs() -> None:
    text = dedent(
        """
        target "api" {
          tags = [
            "ghcr.io/acme/bake-api:latest",
            "registry.bake.acme.example/platform/api:2026",
            "latest",
            "traefik.http.routers.api.rule=Host(`bake-edge.acme.example`)",
          ]
          cache-from = ["type=registry,ref=ghcr.io/acme/bake-api:cache"]
          cache-to = ["type=registry,ref=ghcr.io/acme/bake-cache:cache"]
          contexts = {
            base = "docker-image://ghcr.io/acme/bake-base:stable"
          }
        }
        """
    )

    assert _extract_artifact_container_image_urls(text) == [
        "https://ghcr.io/acme/bake-api",
        "https://registry.bake.acme.example/platform/api",
        "https://ghcr.io/acme/bake-cache",
        "https://ghcr.io/acme/bake-base",
    ]


def test_artifact_container_image_urls_promote_dockerfile_from_flags() -> None:
    text = dedent(
        """
        FROM alpine:3.20 AS builder
        COPY --from=builder /app/dist /srv/app
        COPY --from=ghcr.io/acme/docker-copy-helper:latest /usr/bin/helper /usr/bin/helper
        RUN --mount=type=cache,from=registry.acme.example/buildkit/cache:latest,target=/cache true
        """
    )

    assert _extract_artifact_container_image_urls(text) == [
        "https://hub.docker.com/r/library/alpine",
        "https://ghcr.io/acme/docker-copy-helper",
        "https://registry.acme.example/buildkit/cache",
    ]


def test_artifact_container_image_urls_promote_jenkinsfile_docker_images() -> None:
    text = dedent(
        """
        pipeline {
          agent {
            docker {
              image 'ghcr.io/acme/jenkins-agent:latest'
            }
          }
          stages {
            stage('deploy') {
              steps {
                script {
                  docker.image("registry.jenkins.acme.example/tools/deploy:1.0").inside {
                    sh 'deploy'
                  }
                  docker.build('local-build-only')
                }
              }
            }
          }
        }
        """
    )

    assert _extract_artifact_container_image_urls(text, source_hint="Jenkinsfile") == [
        "https://ghcr.io/acme/jenkins-agent",
        "https://registry.jenkins.acme.example/tools/deploy",
    ]
    assert _extract_artifact_container_image_urls(
        "image 'ghcr.io/acme/source-gated:latest'",
        source_hint="README.md",
    ) == []


def test_artifact_container_image_urls_promote_earthfile_save_image_outputs() -> None:
    text = dedent(
        """
        VERSION 0.8
        build:
          SAVE IMAGE --push ghcr.io/acme/earth-api:prod local-output:latest
          SAVE IMAGE "registry.earth.acme.example/platform/worker:2026"
          SAVE IMAGE --push ${EARTH_IMAGE}
        """
    )

    assert _extract_artifact_container_image_urls(text, source_hint="Earthfile") == [
        "https://ghcr.io/acme/earth-api",
        "https://registry.earth.acme.example/platform/worker",
    ]
    assert _extract_artifact_container_image_urls(text, source_hint="README.md") == []
