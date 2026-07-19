from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest import mock

import pytest

import forge.utils.post.collectors.kubernetes_collector as kubernetes_collector
from forge.utils.post.collectors.filesystem import CollectedFile
from forge.utils.post.collectors.kubernetes_collector import KubernetesCollector


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    return home


@pytest.fixture(autouse=True)
def collector_roe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORGE_ROE_ID", "ROE-TEST")


@pytest.fixture(autouse=True)
def fake_service_account_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "serviceaccount"
    monkeypatch.setattr(kubernetes_collector, "_SERVICE_ACCOUNT_DIR", path)
    return path


@pytest.fixture
def collector(
    tmp_eng_db: Path,
    tmp_path: Path,
    fake_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> KubernetesCollector:
    _ = fake_home
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.delenv("KUBERNETES_SERVICE_PORT", raising=False)
    collector = KubernetesCollector(
        db_path=tmp_eng_db,
        engagement_id=1,
        staging_dir=tmp_path / "stage",
    )
    collector._staging_dir.mkdir()
    monkeypatch.setattr(collector, "_load_clients", lambda: None)
    return collector


def test_discover_kubeconfig(collector: KubernetesCollector, fake_home: Path) -> None:
    kubeconfig_path = fake_home / ".kube" / "config"
    kubeconfig_path.parent.mkdir(parents=True)
    kubeconfig_path.touch()

    artifacts = list(collector.discover())

    assert len(artifacts) == 1
    assert artifacts[0].artifact_family == "kubernetes_config"
    assert artifacts[0].artifact_subtype == "kubeconfig"
    assert artifacts[0].source_path == str(kubeconfig_path)


def test_discover_service_account_artifacts(
    collector: KubernetesCollector,
    fake_service_account_dir: Path,
) -> None:
    sa_dir = fake_service_account_dir
    sa_dir.mkdir(parents=True, exist_ok=True)
    created = [sa_dir / "token", sa_dir / "namespace", sa_dir / "ca.crt"]
    for path in created:
        path.write_text("x")

    artifacts = [
        artifact for artifact in collector.discover()
        if artifact.artifact_family == "kubernetes_credentials"
    ]

    assert {artifact.artifact_subtype for artifact in artifacts} == {
        "service_account_token",
        "service_account_namespace",
        "service_account_ca.crt",
    }

    for path in created:
        if path.exists():
            path.unlink()


def test_discover_kubernetes_env_vars(
    collector: KubernetesCollector,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")

    artifacts = [
        artifact for artifact in collector.discover()
        if artifact.artifact_family == "kubernetes_context"
    ]

    assert len(artifacts) == 1
    assert artifacts[0].artifact_subtype == "env_vars"
    assert artifacts[0].report_safe_summary_fields == {"host": "10.0.0.1", "port": "443"}


def test_collect_kubeconfig(collector: KubernetesCollector, fake_home: Path) -> None:
    kubeconfig_path = fake_home / ".kube" / "config"
    kubeconfig_path.parent.mkdir(parents=True)
    kubeconfig_path.write_text("apiVersion: v1\nclusters: []")

    artifact = next(collector.discover())
    collected_file = collector.collect(artifact)

    assert collected_file is not None
    assert collected_file.path == str(kubeconfig_path)
    assert collected_file.metadata.artifact_family == "kubernetes_config"


def test_collect_kubernetes_env_vars_context(
    collector: KubernetesCollector,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")

    artifact = next(
        artifact
        for artifact in collector.discover()
        if artifact.artifact_family == "kubernetes_context"
    )
    collected_file = collector.collect(artifact)

    assert collected_file is not None
    assert collected_file.path == "os.environ"
    assert collected_file.metadata.artifact_family == "kubernetes_context"


def test_discover_inventory_and_pivot_mapping(
    collector: KubernetesCollector,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    role_rule = SimpleNamespace(resources=["secrets", "pods"], verbs=["get", "exec"])
    role = SimpleNamespace(
        metadata=SimpleNamespace(namespace="default", name="secret-reader"),
        rules=[role_rule],
    )
    role_binding = SimpleNamespace(
        metadata=SimpleNamespace(namespace="default"),
        role_ref=SimpleNamespace(name="secret-reader"),
        subjects=[SimpleNamespace(kind="ServiceAccount", namespace="default", name="builder")],
    )
    pod = SimpleNamespace(
        metadata=SimpleNamespace(namespace="default", name="api-pod"),
        spec=SimpleNamespace(service_account_name="builder"),
    )
    namespace = SimpleNamespace(metadata=SimpleNamespace(name="default"))
    service_account = SimpleNamespace(metadata=SimpleNamespace(namespace="default", name="builder"))
    secret = SimpleNamespace(metadata=SimpleNamespace(namespace="default", name="db-creds"))

    core_v1 = SimpleNamespace(
        list_namespace=lambda: SimpleNamespace(items=[namespace]),
        list_pod_for_all_namespaces=lambda: SimpleNamespace(items=[pod]),
        list_service_account_for_all_namespaces=lambda: SimpleNamespace(items=[service_account]),
        list_secret_for_all_namespaces=lambda: SimpleNamespace(items=[secret]),
        list_namespaced_pod=lambda namespace: SimpleNamespace(items=[pod]),
    )
    rbac_v1 = SimpleNamespace(
        list_role_for_all_namespaces=lambda: SimpleNamespace(items=[role]),
        list_cluster_role=lambda: SimpleNamespace(items=[]),
        list_role_binding_for_all_namespaces=lambda: SimpleNamespace(items=[role_binding]),
        list_cluster_role_binding=lambda: SimpleNamespace(items=[]),
    )
    monkeypatch.setattr(collector, "_load_clients", lambda: (core_v1, rbac_v1))

    artifacts = list(collector.discover())

    inventory = next(artifact for artifact in artifacts if artifact.artifact_family == "kubernetes_inventory")
    pivot = next(artifact for artifact in artifacts if artifact.artifact_family == "kubernetes_pivot_opportunity")

    assert inventory.report_safe_summary_fields["pod_count"] == 1
    assert pivot.source_path == "default/builder"
    assert "default/api-pod" in pivot.report_safe_summary_fields["pod_targets"]
    assert pivot.report_safe_summary_fields["workflow_preview"] == [
        "kubectl exec -n default api-pod -- /bin/sh"
    ]


def test_generate_pivot_workflows_uses_supplied_targets(collector: KubernetesCollector) -> None:
    workflows = collector.generate_pivot_workflows(
        "default/builder",
        pod_targets=["default/api-pod", "default/jobs-pod"],
    )

    assert workflows == [
        "kubectl exec -n default api-pod -- /bin/sh",
        "kubectl exec -n default jobs-pod -- /bin/sh",
    ]


def test_validate_skips_by_default(collector: KubernetesCollector) -> None:
    assert collector.validate(cast(CollectedFile, mock.MagicMock())) is False
