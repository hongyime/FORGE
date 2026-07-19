from __future__ import annotations

from forge.utils.artifact_lambda_config import (
    lambda_config_artifact_label,
    lambda_config_candidates,
)


def _lambda_config() -> dict[str, object]:
    return {
        "FunctionName": "portal",
        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:portal",
        "Runtime": "python3.12",
        "Role": "arn:aws:iam::123456789012:role/service-role/portal-role",
        "KMSKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
        "FunctionUrl": "https://abcde.lambda-url.us-east-1.on.aws/",
        "Code": {"ImageUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/portal:2026-07-19"},
        "Layers": [{"Arn": "arn:aws:lambda:us-east-1:123456789012:layer:shared:3"}],
        "FileSystemConfigs": [{"Arn": "arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-123"}],
        "DeadLetterConfig": {"TargetArn": "arn:aws:sqs:us-east-1:123456789012:portal-dlq"},
        "Environment": {
            "Variables": {
                "SUPPORT_EMAIL": "lambda-owner@acme.example",
                "PORTAL_URL": "https://lambda.acme.example/api",
                "FIREBASE_PROJECT_ID": "lambdafirebase",
                "NEXT_PUBLIC_SUPABASE_PROJECT_REF": "lambdavault",
                "AWS_S3_BUCKET": "lambda-s3-bucket",
            }
        },
    }


def test_lambda_config_labels_are_source_aware() -> None:
    assert lambda_config_artifact_label("lambda-function-configuration.json") == "lambda-function-configuration"
    assert lambda_config_artifact_label("function-configuration.yaml") == "lambda-function-configuration"
    assert lambda_config_artifact_label("lambda-functions.json") == "lambda-function-configuration"
    assert lambda_config_artifact_label("function-url-config.yml") == "lambda-function-url-config"
    assert lambda_config_artifact_label("cache.lambda-config") == "lambda-function-configuration"
    assert lambda_config_artifact_label("function.json") == ""


def test_lambda_config_candidates_cover_function_refs_and_environment_pivots() -> None:
    assert lambda_config_candidates(_lambda_config()) == [
        "aws-lambda-function://arn:aws:lambda:us-east-1:123456789012:function:portal",
        "https://abcde.lambda-url.us-east-1.on.aws/",
        "aws-iam-role://arn:aws:iam::123456789012:role/service-role/portal-role",
        "aws-kms-key://arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
        "https://123456789012.dkr.ecr.us-east-1.amazonaws.com/portal",
        "aws-lambda-layer://arn:aws:lambda:us-east-1:123456789012:layer:shared:3",
        "aws-efs-access-point://arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-123",
        "aws-sqs-queue://arn:aws:sqs:us-east-1:123456789012:portal-dlq",
        "lambda-owner@acme.example",
        "https://lambda.acme.example/api",
        "lambdafirebase",
        "lambdavault",
        "lambda-s3-bucket",
    ]


def test_lambda_config_candidates_support_wrapped_exports_and_skip_templates() -> None:
    assert lambda_config_candidates({"Configuration": _lambda_config()})[:2] == [
        "aws-lambda-function://arn:aws:lambda:us-east-1:123456789012:function:portal",
        "https://abcde.lambda-url.us-east-1.on.aws/",
    ]
    assert lambda_config_candidates({"Functions": [_lambda_config()]})[:1] == [
        "aws-lambda-function://arn:aws:lambda:us-east-1:123456789012:function:portal"
    ]
    assert lambda_config_candidates({"FunctionName": "portal", "FunctionUrl": "https://lambda.example/"}) == [
        "aws-lambda-function://portal",
        "https://lambda.example/",
    ]
    assert lambda_config_candidates({"FunctionName": "{{ name }}", "Runtime": "python3.12"}) == []
    assert lambda_config_candidates({"FunctionName": "portal"}) == []
