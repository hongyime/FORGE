
from __future__ import annotations

from typing import Type

from forge.utils.post.collectors.aws_collector import AwsCollector
from forge.utils.post.collectors.clipboard_collector import ClipboardCollector
from forge.utils.post.collectors.db_collector import DbCollector
from forge.utils.post.collectors.dev_artifacts_collector import DevArtifactsCollector
from forge.utils.post.collectors.docker_collector import DockerCollector
from forge.utils.post.collectors.env_var_collector import EnvVarCollector
from forge.utils.post.collectors.filesystem import BaseCollector, FilesystemCollector
from forge.utils.post.collectors.gcp_collector import GcpCollector
from forge.utils.post.collectors.git_collector import GitCollector
from forge.utils.post.collectors.kubernetes_collector import KubernetesCollector
from forge.utils.post.collectors.npm_collector import NpmCollector
from forge.utils.post.collectors.shell_history_collector import ShellHistoryCollector
from forge.utils.post.collectors.smtp_collector import SmtpCollector
from forge.utils.post.collectors.ssl_collector import SslCollector
from forge.utils.post.collectors.ssh_collector import SshCollector
from forge.utils.post.collectors.ssh_aws_keys import SshAwsKeyCollector
from forge.utils.post.collectors.vault_collector import VaultCollector
from forge.utils.post.collectors.vpn_collector import VpnCollector
from forge.utils.post.collectors.wallet_collector import WalletCollector
from forge.utils.post.collectors.azure_collector import AzureCollector
from forge.utils.post.collectors.iac_cicd_collector import IacCicdCollector

COLLECTOR_REGISTRY: dict[str, Type[BaseCollector]] = {
    "ssh": SshCollector,
    "aws": AwsCollector,
    "env": EnvVarCollector,
    "env_vars": EnvVarCollector,
    "clipboard": ClipboardCollector,
    "filesystem": FilesystemCollector,
    "ssh_aws_keys": SshAwsKeyCollector,
    "kubernetes": KubernetesCollector,
    "gcp": GcpCollector,
    "docker": DockerCollector,
    "azure": AzureCollector,
    "shell_history": ShellHistoryCollector,
    "git": GitCollector,
    "iac_cicd": IacCicdCollector,
    "dev_artifacts": DevArtifactsCollector,
    "db": DbCollector,
    "vault": VaultCollector,
    "vpn": VpnCollector,
    "npm": NpmCollector,
    "ssl": SslCollector,
    "smtp": SmtpCollector,
    "wallet": WalletCollector,
}
