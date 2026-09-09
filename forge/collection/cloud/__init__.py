"""Cloud credential collection helpers for authorized post-exploitation evidence.

Exports the public harvest functions and credential dataclasses for AWS, Azure,
and GCP. All secret material is SHA-256 hashed before being returned; raw
secrets never leave the individual collection modules.
"""

from forge.collection.cloud.aws_credentials import AWSCredential, harvest_aws_credentials
from forge.collection.cloud.azure_credentials import AzureCredential, harvest_azure_credentials
from forge.collection.cloud.gcp_credentials import GCPCredential, harvest_gcp_credentials

__all__ = [
    "AWSCredential",
    "AzureCredential",
    "GCPCredential",
    "harvest_aws_credentials",
    "harvest_azure_credentials",
    "harvest_gcp_credentials",
]
