from __future__ import annotations

from forge.utils.artifact_amplify_client_config import (
    amplify_client_config_artifact_label,
    amplify_client_config_candidates,
    amplify_client_config_text_candidates,
)


def test_amplify_client_config_labels_are_source_aware() -> None:
    assert amplify_client_config_artifact_label("aws-exports.js") == "amplify-client-config"
    assert amplify_client_config_artifact_label("amplifyconfiguration.json") == "amplify-client-config"
    assert amplify_client_config_artifact_label("amplify_outputs.yaml") == "amplify-client-config"
    assert amplify_client_config_artifact_label("not-aws-exports.js") == ""


def test_amplify_client_config_text_candidates_cover_client_refs() -> None:
    text = """
    const awsmobile = {
      aws_project_region: "us-east-1",
      aws_cognito_identity_pool_id: "us-east-1:11111111-2222-3333-4444-555555555555",
      aws_user_pools_id: "us-east-1_AbCd12345",
      aws_user_pools_web_client_id: "abcclient123",
      aws_appsync_graphqlEndpoint: "https://abc123456789.appsync-api.us-east-1.amazonaws.com/graphql?token=secret",
      aws_user_files_s3_bucket: "amplify-client-bucket",
      aws_mobile_analytics_app_id: "pinpoint123",
    };
    """

    assert amplify_client_config_text_candidates(text) == [
        "aws-cognito-identity-pool://us-east-1:11111111-2222-3333-4444-555555555555",
        "aws-cognito-user-pool://us-east-1_AbCd12345",
        "https://abc123456789.appsync-api.us-east-1.amazonaws.com/graphql",
        "aws-appsync-api://us-east-1/abc123456789",
        "s3://amplify-client-bucket",
        "aws-cognito-app-client://us-east-1_AbCd12345/abcclient123",
        "aws-pinpoint-app://us-east-1/pinpoint123",
    ]


def test_amplify_client_config_candidates_cover_nested_outputs() -> None:
    document = {
        "auth": {
            "user_pool_id": "us-east-1_XyZ987",
            "user_pool_client_id": "client987",
            "identity_pool_id": "us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        },
        "data": {
            "url": "https://def987654321.appsync-api.us-west-2.amazonaws.com/graphql?apiKey=secret",
            "aws_region": "us-west-2",
        },
        "storage": {"bucket_name": "amplify-output-bucket"},
    }

    assert amplify_client_config_candidates(document) == [
        "aws-cognito-user-pool://us-east-1_XyZ987",
        "aws-cognito-identity-pool://us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "https://def987654321.appsync-api.us-west-2.amazonaws.com/graphql",
        "aws-appsync-api://us-west-2/def987654321",
        "s3://amplify-output-bucket",
        "aws-cognito-app-client://us-east-1_XyZ987/client987",
    ]


def test_amplify_client_config_candidates_skip_generic_documents() -> None:
    assert amplify_client_config_candidates({"region": "us-east-1"}) == []
    assert amplify_client_config_candidates(
        {
            "userPoolId": "us-east-1_Generic",
            "url": "https://example.com/?token=secret",
            "bucket": "public-assets",
        }
    ) == []
    assert amplify_client_config_candidates({"storage": {"bucket_name": "public-assets"}}) == []
    assert amplify_client_config_candidates(
        {"storage": {"bucket_name": "public-assets"}},
        source_hint="amplify_outputs.json",
    ) == [
        "s3://public-assets"
    ]
    assert amplify_client_config_text_candidates('const config = { region: "us-east-1" };') == []
