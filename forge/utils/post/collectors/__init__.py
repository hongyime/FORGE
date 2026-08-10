from __future__ import annotations

from forge.config import is_offensive_enabled
from forge.utils.post.collectors.db_collector import DbCollector
from forge.utils.post.collectors.aws_collector import AwsCollector
from forge.utils.post.collectors.azure_collector import AzureCollector
from forge.utils.post.collectors.clipboard_collector import ClipboardCollector
from forge.utils.post.collectors.docker_collector import DockerCollector
from forge.utils.post.collectors.env_var_collector import EnvVarCollector
from forge.utils.post.collectors.filesystem import FilesystemCollector
from forge.utils.post.collectors.gcp_collector import GcpCollector
from forge.utils.post.collectors.iac_cicd_collector import IacCicdCollector
from forge.utils.post.collectors.kubernetes_collector import KubernetesCollector
from forge.utils.post.collectors.registry import COLLECTOR_REGISTRY
from forge.utils.post.collectors.shell_history_collector import ShellHistoryCollector
from forge.utils.post.collectors.ssh_aws_keys import SshAwsKeyCollector

__all__ = [
    "FilesystemCollector",
    "COLLECTOR_REGISTRY",
    "SshAwsKeyCollector",
    "EnvVarCollector",
    "ClipboardCollector",
    "KubernetesCollector",
    "GcpCollector",
    "DockerCollector",
    "AzureCollector",
    "ShellHistoryCollector",
    "IacCicdCollector",
    "MssqlCollector",
]

if is_offensive_enabled():
    from forge.utils.post.collectors.browser_creds import BrowserCredCollector
    from forge.utils.post.collectors.win_creds import WinCredCollector

    __all__ += [
        "BrowserCredCollector",
        "WinCredCollector",
    ]
