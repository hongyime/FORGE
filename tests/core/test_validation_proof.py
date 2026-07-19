from __future__ import annotations

import pytest

from forge.utils.validation_proof import parse_validated_detail


def test_parse_validated_detail_preserves_stable_aws_sts_account_id() -> None:
    proof = parse_validated_detail(
        "VALIDATED:aws_sts_get_caller_identity:AccountId=742931608514 UserId=AIDAEXAMPLE"
    )

    assert proof == {
        "validation_status": "VALIDATED",
        "validation_method": "aws_sts_get_caller_identity",
        "validation_proof": "AccountId=742931608514 UserId=AIDAEXAMPLE",
    }


def test_parse_validated_detail_downgrades_sequential_aws_sts_account_id() -> None:
    proof = parse_validated_detail(
        "VALIDATED:aws_sts_get_caller_identity:AccountId=123456789012 UserId=AIDAEXAMPLE"
    )

    assert proof == {
        "validation_status": "UNVERIFIED",
        "validation_method": "aws_sts_get_caller_identity",
        "validation_proof": "",
    }


def test_parse_validated_detail_downgrades_aws_sts_without_account_id() -> None:
    proof = parse_validated_detail(
        "VALIDATED:aws_sts_get_caller_identity:UserId=AIDAEXAMPLE"
    )

    assert proof == {
        "validation_status": "UNVERIFIED",
        "validation_method": "aws_sts_get_caller_identity",
        "validation_proof": "",
    }


@pytest.mark.parametrize(
    ("detail", "method"),
    [
        (
            "VALIDATED:firebase_database_shallow_read:"
            "Firebase project reference responded with non-empty data.",
            "firebase_database_shallow_read",
        ),
        (
            "VALIDATED:firebase_database_node_read:"
            "Firebase database probe confirmed live child-node data after the shallow key probe.",
            "firebase_database_node_read",
        ),
        (
            "VALIDATED:supabase_rest_root:Supabase REST endpoint returned live data.",
            "supabase_rest_root",
        ),
    ],
)
def test_parse_validated_detail_preserves_stable_legacy_cloud_read_proofs(
    detail: str,
    method: str,
) -> None:
    proof = parse_validated_detail(detail)

    assert proof["validation_status"] == "VALIDATED"
    assert proof["validation_method"] == method
    assert proof["validation_proof"]


@pytest.mark.parametrize(
    ("detail", "method"),
    [
        (
            "VALIDATED:firebase_database_shallow_read:"
            "Firebase shallow probe exposed only low-signal scaffold keys.",
            "firebase_database_shallow_read",
        ),
        (
            "VALIDATED:firebase_database_node_read:"
            "Firebase endpoint responded successfully, but no live database payload was confirmed.",
            "firebase_database_node_read",
        ),
        (
            "VALIDATED:supabase_rest_root:"
            "Supabase REST endpoint returned project metadata, but no table data was confirmed.",
            "supabase_rest_root",
        ),
        (
            "VALIDATED:supabase_rest_root:provider returned 200",
            "supabase_rest_root",
        ),
        ("VALIDATED:firebase_database_shallow_read", "firebase_database_shallow_read"),
        ("VALIDATED:firebase_database_node_read:", "firebase_database_node_read"),
        ("VALIDATED:supabase_rest_root", "supabase_rest_root"),
        ("VALIDATED:supabase_rest_root:", "supabase_rest_root"),
        (
            "VALIDATED:supabase_rest_root:Supabase REST endpoint responded successfully.",
            "supabase_rest_root",
        ),
    ],
)
def test_parse_validated_detail_downgrades_low_signal_legacy_cloud_read_proofs(
    detail: str,
    method: str,
) -> None:
    proof = parse_validated_detail(detail)

    assert proof == {
        "validation_status": "UNVERIFIED",
        "validation_method": method,
        "validation_proof": "",
    }


def test_parse_validated_detail_downgrades_unknown_validated_method() -> None:
    proof = parse_validated_detail(
        "VALIDATED:future_provider_success:provider returned 200"
    )

    assert proof == {
        "validation_status": "UNVERIFIED",
        "validation_method": "future_provider_success",
        "validation_proof": "",
    }


@pytest.mark.parametrize(
    ("detail", "method"),
    [
        (
            "VALIDATED:s3_list_bucket:"
            "<ListBucketResult><Contents><Key>prod/customer-records.csv</Key></Contents>"
            "</ListBucketResult>",
            "s3_list_bucket",
        ),
        (
            "VALIDATED:do_spaces_list_bucket:"
            "<ListBucketResult><Contents><Key>reports/engagement-summary.pdf</Key></Contents>"
            "</ListBucketResult>",
            "do_spaces_list_bucket",
        ),
        (
            'VALIDATED:gcs_list_bucket:{"kind":"storage#objects","items":'
            '[{"name":"prod/config.json","bucket":"acme-public-assets"}]}',
            "gcs_list_bucket",
        ),
        (
            "VALIDATED:azure_blob_list_container:"
            "<EnumerationResults><Blobs><Blob><Name>exports/customer-records.csv</Name></Blob>"
            "</Blobs></EnumerationResults>",
            "azure_blob_list_container",
        ),
    ],
)
def test_parse_validated_detail_preserves_stable_cloud_listing_proofs(
    detail: str,
    method: str,
) -> None:
    proof = parse_validated_detail(detail)

    assert proof["validation_status"] == "VALIDATED"
    assert proof["validation_method"] == method
    assert proof["validation_proof"]


@pytest.mark.parametrize(
    ("detail", "method"),
    [
        (
            "VALIDATED:s3_list_bucket:"
            "<ListBucketResult><Contents><Key>sample/test-data.json</Key></Contents>"
            "</ListBucketResult>",
            "s3_list_bucket",
        ),
        (
            "VALIDATED:s3_list_bucket:"
            "<ListBucketResult><Contents><Key>static/js/main.8f3ea4bd.js</Key></Contents>"
            "</ListBucketResult>",
            "s3_list_bucket",
        ),
        (
            "VALIDATED:do_spaces_list_bucket:"
            "<ListBucketResult><Contents><Key>index.html</Key></Contents>"
            "</ListBucketResult>",
            "do_spaces_list_bucket",
        ),
        (
            'VALIDATED:gcs_list_bucket:{"kind":"storage#objects","items":'
            '[{"name":"sample/test-data.json","bucket":"acme-public-assets"}]}',
            "gcs_list_bucket",
        ),
        (
            "VALIDATED:azure_blob_list_container:"
            "<EnumerationResults><Blobs><Blob><Name>assets/logo.svg</Name></Blob>"
            "</Blobs></EnumerationResults>",
            "azure_blob_list_container",
        ),
        (
            "VALIDATED:s3_list_bucket:Bucket listing returned object metadata.",
            "s3_list_bucket",
        ),
    ],
)
def test_parse_validated_detail_downgrades_low_signal_cloud_listing_proofs(
    detail: str,
    method: str,
) -> None:
    proof = parse_validated_detail(detail)

    assert proof == {
        "validation_status": "UNVERIFIED",
        "validation_method": method,
        "validation_proof": "",
    }


@pytest.mark.parametrize(
    ("detail", "method"),
    [
        (
            "VALIDATED:cloudflare_token_verify:Cloudflare token valid: "
            "token_id=abcdef1234567890abcdef1234567890 status=active",
            "cloudflare_token_verify",
        ),
        (
            "VALIDATED:vercel_user_get:Vercel user ok: "
            "user_id=usr_abcdefghijklmnop user_profile_present=true",
            "vercel_user_get",
        ),
        (
            "VALIDATED:netlify_current_user:Netlify user ok: "
            "user_id=netlify-user-123 user_profile_present=true",
            "netlify_current_user",
        ),
        (
            "VALIDATED:notion_users_me:Notion users me ok: "
            "user_id=3c90c3cc-0d44-4b50-8888-8dd25736052a user_profile_present=true",
            "notion_users_me",
        ),
        (
            "VALIDATED:posthog_users_me:PostHog users me ok: host=eu.posthog.com "
            "user_id=018f9b7d-1234-4567-9abc-def012345678 user_profile_present=true",
            "posthog_users_me",
        ),
        (
            "VALIDATED:sentry_list_organizations:Sentry organizations ok: org_id=4505524236910592 "
            "org_slug_present=true org_slug_stable=true org_slug_hash=d2836b7de9447c4a",
            "sentry_list_organizations",
        ),
        (
            "VALIDATED:github_user_api:GitHub user ok: "
            "user_id=738251 login=testuser user_profile_present=true "
            "profile_url_matches_login=true",
            "github_user_api",
        ),
        (
            "VALIDATED:gitlab_current_user_api:GitLab user ok: "
            "user_id=739251 username=delta-ops user_profile_present=true "
            "profile_url_matches_login=true",
            "gitlab_current_user_api",
        ),
        (
            "VALIDATED:huggingface_whoami_v2:Hugging Face auth ok: "
            "user=model-owner user_profile_present=true",
            "huggingface_whoami_v2",
        ),
        (
            "VALIDATED:discord_current_user:Discord bot auth ok: "
            "bot_id=739251864203918576 bot_profile_present=true",
            "discord_current_user",
        ),
        (
            "VALIDATED:telegram_get_me:Telegram bot auth ok: "
            "bot_id=725419863 bot_profile_present=true",
            "telegram_get_me",
        ),
        (
            "VALIDATED:sendgrid_profile_api:SendGrid profile ok: "
            "proof=profile profile_hash=0123456789abcdef email_present=true",
            "sendgrid_profile_api",
        ),
        (
            "VALIDATED:sendgrid_profile_api:SendGrid scopes accessible: "
            "count=2 scope_hash=0123456789abcdef",
            "sendgrid_profile_api",
        ),
        (
            "VALIDATED:stripe_balance_api:Stripe balance accessible: "
            "mode=live currencies=sgd,usd balances=available:1,pending:1",
            "stripe_balance_api",
        ),
        (
            "VALIDATED:twilio_account_api:Twilio account accessible: "
            "sid=AC1234567890abcdef1234567890abcdef status=active type=Full",
            "twilio_account_api",
        ),
        (
            "VALIDATED:slack_auth_test:Slack auth ok: actor_id=U7A3C9K2 team_id=T9B2D6F4",
            "slack_auth_test",
        ),
        (
            "VALIDATED:azure_blob_list_containers_shared_key:Azure blob list accessible: "
            "account=comboartifactblob containers=1",
            "azure_blob_list_containers_shared_key",
        ),
    ],
)
def test_parse_validated_detail_preserves_stable_profile_provider_proofs(
    detail: str,
    method: str,
) -> None:
    proof = parse_validated_detail(detail)

    assert proof["validation_status"] == "VALIDATED"
    assert proof["validation_method"] == method
    assert proof["validation_proof"]


@pytest.mark.parametrize(
    ("detail", "method"),
    [
        (
            "VALIDATED:cloudflare_token_verify:Cloudflare token valid: "
            "token_id=0000000000000000 status=active",
            "cloudflare_token_verify",
        ),
        (
            "VALIDATED:cloudflare_token_verify:Cloudflare token valid: "
            "token_id=abcdef1234567890abcdef1234567890",
            "cloudflare_token_verify",
        ),
        (
            "VALIDATED:cloudflare_token_verify:Cloudflare token valid: "
            "token_id=dummy_abcdef123456 status=active",
            "cloudflare_token_verify",
        ),
        (
            "VALIDATED:vercel_user_get:Vercel user ok: "
            "user_id=usr_0000000000000000 user_profile_present=true",
            "vercel_user_get",
        ),
        (
            "VALIDATED:vercel_user_get:Vercel user ok: "
            "user_id=usr_123456 user_profile_present=true",
            "vercel_user_get",
        ),
        (
            "VALIDATED:vercel_user_get:Vercel user ok: "
            "user_id=user_test user_profile_present=true",
            "vercel_user_get",
        ),
        (
            "VALIDATED:vercel_user_get:Vercel user ok: "
            "user_id=fake-user-123 user_profile_present=true",
            "vercel_user_get",
        ),
        (
            "VALIDATED:netlify_current_user:Netlify user ok: user_id=netlify-user-123",
            "netlify_current_user",
        ),
        (
            "VALIDATED:netlify_current_user:Netlify user ok: "
            "user_id=netlify-placeholder user_profile_present=true",
            "netlify_current_user",
        ),
        (
            "VALIDATED:netlify_current_user:Netlify user ok: "
            "user_id=mock-user-123 user_profile_present=true",
            "netlify_current_user",
        ),
        (
            "VALIDATED:notion_users_me:Notion users me ok: "
            "user_id=00000000-0000-0000-0000-000000000000 user_profile_present=true",
            "notion_users_me",
        ),
        (
            "VALIDATED:notion_users_me:Notion users me ok: "
            "user_id=12345678-9012-3456-7890-123456789012 user_profile_present=true",
            "notion_users_me",
        ),
        (
            "VALIDATED:posthog_users_me:PostHog users me ok: host=preview.example.com "
            "user_id=018f9b7d-1234-4567-9abc-def012345678 user_profile_present=true",
            "posthog_users_me",
        ),
        (
            "VALIDATED:posthog_users_me:PostHog users me ok: host=eu.posthog.com "
            "user_id=changeme-user-123 user_profile_present=true",
            "posthog_users_me",
        ),
        (
            "VALIDATED:sentry_list_organizations:Sentry organizations ok: org_id=0000000000000000 "
            "org_slug_present=true org_slug_stable=true",
            "sentry_list_organizations",
        ),
        (
            "VALIDATED:sentry_list_organizations:Sentry organizations ok: org_id=4505524236910592 "
            "org_slug_present=true org_slug_stable=true",
            "sentry_list_organizations",
        ),
        (
            "VALIDATED:sentry_list_organizations:Sentry organizations ok: org_id=4505524236910592 "
            "org_slug_present=true org_slug_stable=true org_slug_hash=0000000000000000",
            "sentry_list_organizations",
        ),
        (
            "VALIDATED:github_user_api:GitHub user ok: "
            "user_id=123456 login=testuser user_profile_present=true",
            "github_user_api",
        ),
        (
            "VALIDATED:github_user_api:GitHub user ok: "
            "user_id=738251 login=testuser user_profile_present=true",
            "github_user_api",
        ),
        (
            "VALIDATED:github_user_api:GitHub user ok: "
            "user_id=738251 login=testuser user_profile_present=true "
            "profile_url_matches_login=false",
            "github_user_api",
        ),
        (
            "VALIDATED:gitlab_current_user_api:GitLab user ok: "
            "user_id=42 username=service user_profile_present=true",
            "gitlab_current_user_api",
        ),
        (
            "VALIDATED:gitlab_current_user_api:GitLab user ok: "
            "user_id=739251 username=delta-ops user_profile_present=true",
            "gitlab_current_user_api",
        ),
        (
            "VALIDATED:gitlab_current_user_api:GitLab user ok: "
            "user_id=739251 username=delta-ops user_profile_present=true "
            "profile_url_matches_login=false",
            "gitlab_current_user_api",
        ),
        (
            "VALIDATED:google_generative_language_models_list:Google Generative Language models ok: "
            "models=1 sample=gemini-placeholder",
            "google_generative_language_models_list",
        ),
        (
            "VALIDATED:google_generative_language_models_list:Google Generative Language models ok: "
            "models=2 sample=models/gemini-2.5-flash,models/text-embedding-004",
            "google_generative_language_models_list",
        ),
        (
            "VALIDATED:google_generative_language_models_list:Google Generative Language models ok: "
            "models=1 sample=models/vendor-model-alpha",
            "google_generative_language_models_list",
        ),
        (
            "VALIDATED:openai_models_list:OpenAI models ok: models=1 sample=gpt-4o-mini",
            "openai_models_list",
        ),
        (
            "VALIDATED:openai_models_list:OpenAI models ok: models=1 sample=vendor-model-alpha",
            "openai_models_list",
        ),
        (
            "VALIDATED:anthropic_models_list:Anthropic models ok: "
            "models=1 sample=claude-3-5-sonnet-20241022",
            "anthropic_models_list",
        ),
        (
            "VALIDATED:anthropic_models_list:Anthropic models ok: "
            "models=1 sample=sonnet-placeholder-2026",
            "anthropic_models_list",
        ),
        (
            "VALIDATED:huggingface_whoami_v2:Hugging Face auth ok: "
            "user=workspace user_profile_present=true",
            "huggingface_whoami_v2",
        ),
        (
            "VALIDATED:huggingface_whoami_v2:Hugging Face auth ok: "
            "user=demo-user user_profile_present=true",
            "huggingface_whoami_v2",
        ),
        (
            "VALIDATED:huggingface_whoami_v2:Hugging Face auth ok: "
            "user=test-user user_profile_present=true",
            "huggingface_whoami_v2",
        ),
        (
            "VALIDATED:discord_current_user:Discord bot auth ok: "
            "bot_id=123456789012345678 bot_profile_present=true",
            "discord_current_user",
        ),
        (
            "VALIDATED:telegram_get_me:Telegram bot auth ok: "
            "bot_id=123456 bot_profile_present=true",
            "telegram_get_me",
        ),
        (
            "VALIDATED:datadog_api_key_validate:Datadog API key valid: site=datadoghq.eu",
            "datadog_api_key_validate",
        ),
        (
            "VALIDATED:datadog_api_key_validate:Datadog API key valid: "
            "site=datadoghq.eu proof=valid_true",
            "datadog_api_key_validate",
        ),
        (
            "VALIDATED:datadog_api_key_validate:Datadog API key valid: site=unknown",
            "datadog_api_key_validate",
        ),
        (
            "VALIDATED:sendgrid_profile_api:SendGrid profile ok: "
            "proof=profile profile_hash=0000000000000000 email_present=true",
            "sendgrid_profile_api",
        ),
        (
            "VALIDATED:sendgrid_profile_api:SendGrid scopes accessible: count=2",
            "sendgrid_profile_api",
        ),
        (
            "VALIDATED:sendgrid_profile_api:SendGrid scopes accessible: "
            "count=2 scope_hash=0000000000000000",
            "sendgrid_profile_api",
        ),
        (
            "VALIDATED:stripe_balance_api:Stripe balance accessible: "
            "mode=unknown currencies=sgd balances=available:1",
            "stripe_balance_api",
        ),
        (
            "VALIDATED:stripe_balance_api:Stripe balance accessible: "
            "mode=test currencies=usd balances=available:1,pending:0",
            "stripe_balance_api",
        ),
        (
            "VALIDATED:stripe_balance_api:Stripe balance accessible: mode=live currencies=usd",
            "stripe_balance_api",
        ),
        (
            "VALIDATED:stripe_balance_api:Stripe balance accessible: "
            "mode=live currencies=usd,unknown balances=available:1,pending:0",
            "stripe_balance_api",
        ),
        (
            "VALIDATED:mailchimp_ping_api:Mailchimp ping ok: dc=us1 health=Everything's Chimpy!",
            "mailchimp_ping_api",
        ),
        (
            "VALIDATED:mailchimp_ping_api:Mailchimp ping ok: "
            "dc=us1 health=Everything's Chimpy! placeholder",
            "mailchimp_ping_api",
        ),
        (
            "VALIDATED:twilio_account_api:Twilio account accessible: "
            "sid=AC00000000000000000000000000000000 status=active type=Full",
            "twilio_account_api",
        ),
        (
            "VALIDATED:twilio_account_api:Twilio account accessible: "
            "sid=AC1234567890abcdef1234567890abcdef status=suspended type=Full",
            "twilio_account_api",
        ),
        (
            "VALIDATED:twilio_account_api:Twilio account accessible: "
            "sid=AC1234567890abcdef1234567890abcdef status=closed type=Full",
            "twilio_account_api",
        ),
        (
            "VALIDATED:slack_auth_test:Slack auth ok: actor_id=U1234567 team_id=T7654321",
            "slack_auth_test",
        ),
        (
            "VALIDATED:slack_auth_test:Slack auth ok: actor_id=B000000 team_id=T7654321",
            "slack_auth_test",
        ),
        (
            "VALIDATED:azure_blob_list_containers_shared_key:Azure blob list accessible: "
            "account=demo containers=1",
            "azure_blob_list_containers_shared_key",
        ),
    ],
)
def test_parse_validated_detail_downgrades_low_signal_profile_provider_proofs(
    detail: str,
    method: str,
) -> None:
    proof = parse_validated_detail(detail)

    assert proof == {
        "validation_status": "UNVERIFIED",
        "validation_method": method,
        "validation_proof": "",
    }
