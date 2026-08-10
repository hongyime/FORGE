from __future__ import annotations

from forge.utils.artifact_ecs_task_definition import (
    ecs_task_definition_artifact_label,
    ecs_task_definition_candidates,
)


def _task_definition() -> dict[str, object]:
    return {
        "family": "portal",
        "taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/portal:7",
        "containerDefinitions": [
            {
                "name": "api",
                "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/portal:2026-07-19",
                "environment": [
                    {"name": "SUPPORT_EMAIL", "value": "ecs-owner@acme.example"},
                    {"name": "PORTAL_URL", "value": "https://ecs.acme.example/api"},
                    {"name": "FIREBASE_PROJECT_ID", "value": "ecsfirebase"},
                    {"name": "NEXT_PUBLIC_SUPABASE_PROJECT_REF", "value": "ecsvault"},
                    {"name": "AWS_S3_BUCKET", "value": "ecs-s3-bucket"},
                ],
                "secrets": [
                    {
                        "name": "DB_PASSWORD",
                        "valueFrom": (
                            "arn:aws:secretsmanager:us-east-1:123456789012:"
                            "secret:prod/db-AbCd:password::"
                        ),
                    },
                    {
                        "name": "PAYMENT_KEY",
                        "valueFrom": "arn:aws:ssm:us-east-1:123456789012:parameter/prod/payment/key",
                    },
                ],
                "repositoryCredentials": {
                    "credentialsParameter": (
                        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/repo-AbCd"
                    )
                },
            }
        ],
    }


def test_ecs_task_definition_labels_are_source_aware() -> None:
    assert ecs_task_definition_artifact_label("ecs-task-definition.json") == "ecs-task-definition"
    assert ecs_task_definition_artifact_label("ecs-task-definition.yaml") == "ecs-task-definition"
    assert ecs_task_definition_artifact_label("task-definition.json") == "ecs-task-definition"
    assert ecs_task_definition_artifact_label("task-definition.yml") == "ecs-task-definition"
    assert (
        ecs_task_definition_artifact_label("service.task-definition.json") == "ecs-task-definition"
    )
    assert ecs_task_definition_artifact_label("cache.ecs-task-definition") == "ecs-task-definition"
    assert ecs_task_definition_artifact_label("definition.json") == ""


def test_ecs_task_definition_candidates_cover_task_refs_and_container_data() -> None:
    assert ecs_task_definition_candidates(_task_definition()) == [
        "aws-ecs-task-definition://arn:aws:ecs:us-east-1:123456789012:task-definition/portal:7",
        "https://123456789012.dkr.ecr.us-east-1.amazonaws.com/portal",
        "ecs-owner@acme.example",
        "https://ecs.acme.example/api",
        "ecsfirebase",
        "ecsvault",
        "ecs-s3-bucket",
        "aws-secretsmanager://arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCd",
        "aws-parameterstore://arn:aws:ssm:us-east-1:123456789012:parameter/prod/payment/key",
        "aws-secretsmanager://arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/repo-AbCd",
    ]


def test_ecs_task_definition_candidates_support_wrapped_exports_and_skip_templates() -> None:
    assert ecs_task_definition_candidates({"taskDefinition": _task_definition()})[:2] == [
        "aws-ecs-task-definition://arn:aws:ecs:us-east-1:123456789012:task-definition/portal:7",
        "https://123456789012.dkr.ecr.us-east-1.amazonaws.com/portal",
    ]
    assert (
        ecs_task_definition_candidates({"family": "{{ family }}", "containerDefinitions": []}) == []
    )
    assert ecs_task_definition_candidates({"family": "portal"}) == []
