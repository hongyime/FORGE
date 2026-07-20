from __future__ import annotations

from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.utils.artifact_helm_index import helm_index_chart_package_urls


def test_helm_index_resolves_relative_chart_archives_only() -> None:
    payload = dedent(
        """
        apiVersion: v1
        entries:
          api:
            - version: 1.2.3
              urls:
                - charts/api-1.2.3.tgz
                - ../archive/api-1.2.3.tar.gz
                - https://cdn.acme.example/api-1.2.3.tgz
                - charts/${TENANT}.tgz
                - charts/readme.txt
        """
    )

    assert helm_index_chart_package_urls(
        payload,
        source_hint="https://charts.acme.example/index.yaml",
        base_url="https://charts.acme.example/index.yaml",
    ) == [
        "https://charts.acme.example/charts/api-1.2.3.tgz",
        "https://charts.acme.example/archive/api-1.2.3.tar.gz",
    ]


def test_helm_index_requires_source_shape_and_remote_base() -> None:
    payload = """
apiVersion: v1
entries:
  api:
    - urls: [charts/api-1.2.3.tgz]
"""

    assert (
        helm_index_chart_package_urls(
            payload,
            source_hint="values.yaml",
            base_url="https://charts.acme.example/index.yaml",
        )
        == []
    )
    assert (
        helm_index_chart_package_urls(
            "entries:\n  api: []",
            source_hint="https://charts.acme.example/index.yaml",
            base_url="https://charts.acme.example/index.yaml",
        )
        == []
    )
    assert (
        helm_index_chart_package_urls(
            payload,
            source_hint="index.yaml",
            base_url="C:/tmp/index.yaml",
        )
        == []
    )


def test_artifact_url_family_extracts_helm_index_chart_urls(tmp_path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = """
apiVersion: v1
entries:
  api:
    - urls:
        - charts/api-1.2.3.tgz
        - charts/${TENANT}.tgz
"""

    assert processor._artifact_text_url_family_candidates(
        "helm_index",
        text=payload,
        source_file="https://charts.acme.example/index.yaml",
    ) == ["https://charts.acme.example/charts/api-1.2.3.tgz"]


def test_generic_url_discovery_includes_helm_index_chart_urls(tmp_path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = """
apiVersion: v1
entries:
  api:
    - urls:
        - charts/api-1.2.3.tgz
"""

    batch = processor._collect_generic_text_discovery_family(
        "urls",
        text=payload,
        source_file="https://charts.acme.example/index.yaml",
    )

    assert batch.urls == ["https://charts.acme.example/charts/api-1.2.3.tgz"]
