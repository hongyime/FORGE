from __future__ import annotations

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_terraform_state_resource_value_iterator_preserves_state_order() -> None:
    payload = {
        "resources": [
            {
                "type": "aws_s3_bucket",
                "instances": [{"attributes": {"bucket": "legacy-bucket"}}],
            }
        ],
        "values": {
            "root_module": {
                "resources": [
                    {
                        "type": "google_storage_bucket",
                        "values": {"name": "root-gcs"},
                    }
                ],
                "child_modules": [
                    {
                        "resources": [
                            {
                                "type": "google_firebase_project",
                                "values": {"project": "child-firebase"},
                            }
                        ]
                    }
                ],
            }
        },
        "prior_state": {
            "values": {
                "root_module": {
                    "resources": [
                        {
                            "type": "azurerm_storage_container",
                            "values": {
                                "name": "archive",
                                "storage_account_id": (
                                    "/subscriptions/000/resourceGroups/rg/"
                                    "providers/Microsoft.Storage/"
                                    "storageAccounts/acmeacct"
                                ),
                            },
                        }
                    ]
                }
            }
        },
    }

    assert ArtifactQueueProcessor._iter_terraform_state_resource_values(payload) == [
        ("aws_s3_bucket", {"bucket": "legacy-bucket"}),
        ("google_storage_bucket", {"name": "root-gcs"}),
        ("google_firebase_project", {"project": "child-firebase"}),
        (
            "azurerm_storage_container",
            {
                "name": "archive",
                "storage_account_id": (
                    "/subscriptions/000/resourceGroups/rg/"
                    "providers/Microsoft.Storage/storageAccounts/acmeacct"
                ),
            },
        ),
    ]
