from __future__ import annotations

from forge.utils.artifact_secret_provider_class import secret_provider_class_candidates


def test_secret_provider_class_candidates_cover_azure_aws_gcp_and_vault() -> None:
    azure = {
        "apiVersion": "secrets-store.csi.x-k8s.io/v1",
        "kind": "SecretProviderClass",
        "metadata": {"name": "azure-spc", "namespace": "prod"},
        "spec": {
            "provider": "azure",
            "parameters": {
                "keyvaultName": "spckv",
                "objects": """
                array:
                  - |
                    objectName: db-password
                    objectType: secret
                  - |
                    objectName: tls-key
                    objectType: key
                """,
            },
        },
    }
    aws = {
        "kind": "SecretProviderClass",
        "metadata": {"name": "aws-spc"},
        "spec": {
            "provider": "aws",
            "parameters": {
                "region": "us-east-1",
                "objects": [
                    {
                        "objectName": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api-AbCd",
                        "objectType": "secretsmanager",
                    },
                    {"objectName": "/prod/payment/key", "objectType": "ssmparameter"},
                ],
            },
        },
    }
    gcp = {
        "kind": "SecretProviderClass",
        "metadata": {"name": "gcp-spc"},
        "spec": {
            "provider": "gcp",
            "parameters": {
                "projectID": "gcp-prod-123",
                "secrets": """
                - resourceName: projects/gcp-prod-123/secrets/api-token/versions/latest
                """,
            },
        },
    }
    vault = {
        "kind": "SecretProviderClass",
        "metadata": {"name": "vault-spc"},
        "spec": {
            "provider": "vault",
            "parameters": {
                "vaultAddress": "vault.spc.example",
                "objects": [{"secretPath": "secret/data/app"}],
            },
        },
    }

    assert secret_provider_class_candidates(azure) == [
        "secret-provider-class://prod/azure-spc",
        "https://spckv.vault.azure.net",
        "https://spckv.vault.azure.net/secrets/db-password",
        "https://spckv.vault.azure.net/keys/tls-key",
    ]
    assert secret_provider_class_candidates(aws) == [
        "secret-provider-class://aws-spc",
        "aws-secretsmanager://arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/api-AbCd",
        "aws-parameterstore://us-east-1/prod/payment/key",
    ]
    assert secret_provider_class_candidates(gcp) == [
        "secret-provider-class://gcp-spc",
        "gcp-secretmanager://gcp-prod-123",
        "gcp-secretmanager://gcp-prod-123/api-token",
    ]
    assert secret_provider_class_candidates(vault) == [
        "secret-provider-class://vault-spc",
        "https://vault.spc.example",
        "hashicorp-vault://vault.spc.example",
        "hashicorp-vault://vault.spc.example/secret/data/app",
    ]


def test_secret_provider_class_candidates_ignore_non_csi_manifests_and_templates() -> None:
    assert secret_provider_class_candidates({"kind": "Secret", "metadata": {"name": "plain"}}) == []
    assert (
        secret_provider_class_candidates(
            {
                "kind": "SecretProviderClass",
                "metadata": {"name": "{{ template }}"},
                "spec": {
                    "provider": "azure",
                    "parameters": {
                        "keyvaultName": "{{ vault }}",
                        "objects": "objectName: {{ secret }}\nobjectType: secret",
                    },
                },
            }
        )
        == []
    )
