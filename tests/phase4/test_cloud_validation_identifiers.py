from __future__ import annotations

from forge.phase4 import cloud_validate


def test_non_cloud_validation_identifier_parser_rejects_low_signal_success_details() -> None:
    assert cloud_validate._validated_identifier_from_detail(
        "aws",
        "AWS AccountId: unknown",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "aws",
        "AWS AccountId: 000000000000",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub login: unknown",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub login: null",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub login: aaaaaaaa",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub login: placeholder",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub user ok: user_id=123456 login=admin user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub login: testuser",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub user ok: user_id=123456 login=testuser",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub user ok: user_id=123456 login=testuser user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub user ok: user_id=738251 login=testuser user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub user ok: user_id=738251 login=testuser user_profile_present=true "
        "profile_url_matches_login=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub user ok: user_id=738251 login=placeholderuser user_profile_present=true "
        "profile_url_matches_login=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "github",
        "GitHub user ok: user_id=738251 login=acmebot user_profile_present=true "
        "profile_url_matches_login=true",
    ) == "acmebot"
    assert cloud_validate._validated_identifier_from_detail(
        "gitlab",
        "GitLab user ok: username=unknown",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "gitlab",
        "GitLab user ok: username=undefined",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "gitlab",
        "GitLab user ok: username=000000",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "gitlab",
        "GitLab user ok: username=sample",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "gitlab",
        "GitLab user ok: user_id=42 username=service user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "gitlab",
        "GitLab user ok: username=delta-ops",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "gitlab",
        "GitLab user ok: user_id=42 username=delta-ops",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "gitlab",
        "GitLab user ok: user_id=123456 username=delta-ops user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "gitlab",
        "GitLab user ok: user_id=739251 username=delta-ops user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "gitlab",
        "GitLab user ok: user_id=739251 username=delta-ops user_profile_present=true "
        "profile_url_matches_login=true",
    ) == "delta-ops"
    assert cloud_validate._validated_identifier_from_detail(
        "google",
        "Google Generative Language models ok: models=0",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "google",
        "Google Generative Language models ok: models=2",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "google",
        "Google Generative Language models ok: models=2 sample=models/test,unknown",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "openai",
        "OpenAI models ok: models=1 sample=placeholder",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "openai",
        "OpenAI models ok: models=1 sample=vendor-model-alpha",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "anthropic",
        "Anthropic models ok: models=1 sample=test",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "anthropic",
        "Anthropic models ok: models=1 sample=sonnet-placeholder-2026",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "stripe",
        "Stripe balance accessible: mode=unknown currencies=unknown",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "stripe",
        "Stripe balance accessible: mode=live currencies=none balances=available:0,pending:0",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "stripe",
        "Stripe balance accessible: mode=test currencies=unknown balances=available:1,pending:0",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "stripe",
        "Stripe balance accessible: mode=test currencies=usd balances=available:1,pending:0",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "stripe",
        "Stripe balance accessible: mode=live currencies=usd",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "stripe",
        "Stripe balance accessible: mode=live currencies=usd,unknown balances=available:1,pending:0",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "stripe",
        "Stripe balance accessible: mode=live currencies=aaa balances=available:1,pending:0",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "datadog",
        "Datadog API key valid: site=unknown",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "datadog",
        "Datadog API key valid: site=example.com",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "datadog",
        "Datadog API key valid: site=datadoghq.eu",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "datadog",
        "Datadog API key valid: site=datadoghq.eu proof=valid_true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "twilio",
        "Twilio account accessible: sid=AC00000000000000000000000000000000 status=active",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "twilio",
        "Twilio account accessible: sid=AC1234567890abcdef1234567890abcdef status=active",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "twilio",
        "Twilio account accessible: sid=AC1234567890abcdef1234567890abcdef",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "twilio",
        "Twilio account accessible: sid=AC1234567890abcdef1234567890abcdef status=unknown",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "twilio",
        "Twilio account accessible: sid=AC1234567890abcdef1234567890abcdef status=suspended",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "twilio",
        "Twilio account accessible: sid=AC1234567890abcdef1234567890abcdef status=closed",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sendgrid",
        "SendGrid profile ok: proof=profile",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sendgrid",
        "SendGrid profile ok: proof=profile email_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sendgrid",
        "SendGrid profile ok: proof=profile profile_hash=0000000000000000 email_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sendgrid",
        "SendGrid scopes accessible",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sendgrid",
        "SendGrid scopes accessible: count=0",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sendgrid",
        "SendGrid scopes accessible: count=2",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sendgrid",
        "SendGrid scopes accessible: count=2 scope_hash=0000000000000000",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "mailchimp",
        "Mailchimp ping ok: dc=us1",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "mailchimp",
        "Mailchimp ping ok: dc=us1 health=placeholder",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "mailchimp",
        "Mailchimp ping ok: dc=us1 health=not chimpy",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "mailchimp",
        "Mailchimp ping ok: dc=us1 health=Everything's Chimpy! placeholder",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "mailchimp",
        "Mailchimp ping ok: dc=eu1 health=Everything's Chimpy!",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "azure",
        "Azure blob list accessible: account=acmestorage",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "azure",
        "Azure blob list accessible: account=acmestorage containers=0",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "azure",
        "Azure blob list accessible: account=aaaaaaaaaaaa containers=2",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "azure",
        "Azure blob list accessible: account=test containers=2",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "slack",
        "Slack auth ok: token accepted",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "slack",
        "Slack auth ok: actor_id=unknown team_id=T000",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "slack",
        "Slack auth ok: actor_id=UAAAA team_id=TAAAA",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "slack",
        "Slack auth ok: actor_id=U123 team_id=T123",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "slack",
        "Slack auth ok: actor_id=U1234567 team_id=T7654321",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "slack",
        "Slack auth ok: actor_id=U1234567",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "slack",
        "Slack auth ok: team_id=T7654321",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "cloudflare",
        "Cloudflare token valid: token_id=abcdef1234567890abcdef1234567890 status=pending",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "cloudflare",
        "Cloudflare token valid: token_id=00000000000000000000000000000000 status=active",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "cloudflare",
        "Cloudflare token valid: token_id=placeholder status=active",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "cloudflare",
        "Cloudflare token valid: token_id=dummy_abcdef123456 status=active",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "discord",
        "Discord bot auth ok: bot_id=000000000000000000",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "discord",
        "Discord bot auth ok: bot_id=123456789012345678",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "discord",
        "Discord bot auth ok: bot_id=123456789012345678 bot_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "telegram",
        "Telegram bot auth ok: bot_id=777777777",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "telegram",
        "Telegram bot auth ok: bot_id=765432109",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "telegram",
        "Telegram bot auth ok: bot_id=765432109 bot_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user response missing user id",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user response missing user proof",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user ok: user_id=unknown",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user ok: user_id=usr_abcdefghijklmnop",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user ok: user_id=aaaaaaaaaaaaaaaa",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user ok: user_id=usr_000000000000",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user ok: user_id=placeholder",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user ok: user_id=fake-user-123 user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "netlify",
        "Netlify user response missing user id",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "netlify",
        "Netlify user response missing user proof",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "netlify",
        "Netlify user ok: user_id=null",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "netlify",
        "Netlify user ok: user_id=netlify-user-123",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "netlify",
        "Netlify user ok: user_id=000000000000",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "netlify",
        "Netlify user ok: user_id=user-aaaaaaaaaaaa",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user ok: user_id=usr_placeholder user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user ok: user_id=user_test user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "netlify",
        "Netlify user ok: user_id=netlify-placeholder user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "netlify",
        "Netlify user ok: user_id=mock-user-123 user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "netlify",
        "Netlify user ok: user_id=sample",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "eu.posthog.com: PostHog users/@me response missing user id",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "eu.posthog.com: PostHog users/@me response missing user proof",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=eu.posthog.com user_id=undefined",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=eu.posthog.com "
        "user_id=018f9b7d-1234-4567-9abc-def012345678",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=unknown "
        "user_id=018f9b7d-1234-4567-9abc-def012345678 user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=example.com "
        "user_id=018f9b7d-1234-4567-9abc-def012345678 user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=eu.posthog.com user_id=zzzzzzzzzzzz",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=eu.posthog.com user_id=user-000000000000",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=eu.posthog.com user_id=test",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=eu.posthog.com "
        "user_id=018f9b7d-placeholder user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=eu.posthog.com "
        "user_id=changeme-user-123 user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=eu.posthog.com "
        "user_id=12345678-9012-3456-7890-123456789012 user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "huggingface",
        "Hugging Face auth ok: user=unknown",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "huggingface",
        "Hugging Face auth ok: user=----",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "huggingface",
        "Hugging Face auth ok: user=aaaaaaaa",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "huggingface",
        "Hugging Face auth ok: user=test",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "huggingface",
        "Hugging Face auth ok: user=demo-user user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "huggingface",
        "Hugging Face auth ok: user=test-user user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "huggingface",
        "Hugging Face auth ok: user=model-owner",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "huggingface",
        "Hugging Face auth ok: user=model-owner user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "huggingface",
        "Hugging Face auth ok: user=workspace user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "notion",
        f"Notion users me ok: user_id={'-' * 36}",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "notion",
        "Notion users me ok: user_id=00000000-0000-0000-0000-000000000000",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "notion",
        "Notion users me ok: user_id=12345678-9012-3456-7890-123456789012 "
        "user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "notion",
        "Notion users me ok: user_id=3c90c3cc-0d44-4b50-8888-8dd25736052a",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sentry",
        "Sentry organizations response missing organization proof",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sentry",
        "Sentry organizations ok: org_id=0000000000000000 org_slug_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sentry",
        "Sentry organizations ok: org_id=4505524236910592",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sentry",
        "Sentry organizations ok: org_id=4505524236910592 org_slug_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sentry",
        "Sentry organizations ok: org_id=4505524236910592 "
        "org_slug_present=true org_slug_stable=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "sentry",
        "Sentry organizations ok: org_id=4505524236910592 "
        f"org_slug_present=true org_slug_stable=true org_slug_hash={'0' * 64}",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "notion",
        "Notion users me ok: user_id=3c90c3cc-0d44-4b50-8888-8dd25736052a "
        "user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "notion",
        "Notion users me ok: user_id=3c90c3cc-0d44-4b50-8888-8dd25736052a "
        "user_profile_present=true profile_hash=0123456789abcdef",
    ) == "3c90c3cc-0d44-4b50-8888-8dd25736052a"
    assert cloud_validate._validated_identifier_from_detail(
        "huggingface",
        "Hugging Face auth ok: user=acme-mlops user_profile_present=true",
    ) == "acme-mlops"
    assert cloud_validate._validated_identifier_from_detail(
        "sentry",
        "Sentry organizations ok: org_id=4505524236910592 "
        "org_slug_present=true org_slug_stable=true org_slug_hash=d2836b7de9447c4a",
    ) == "4505524236910592"
    assert cloud_validate._validated_identifier_from_detail(
        "google",
        "Google Generative Language models ok: models=2 sample=models/gemini-2.5-flash",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "openai",
        "OpenAI models ok: models=2 sample=gpt-4o-mini,text-embedding-3-small",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "anthropic",
        "Anthropic models ok: models=2 sample=claude-sonnet-4-5,claude-haiku-4-5",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "stripe",
        "Stripe balance accessible: mode=live currencies=sgd,usd balances=available:1,pending:1",
    ) == "live/sgd,usd"
    assert cloud_validate._validated_identifier_from_detail(
        "sendgrid",
        "SendGrid profile ok: proof=profile profile_hash=0123456789abcdef email_present=true",
    ) == "profile/0123456789abcdef"
    assert cloud_validate._validated_identifier_from_detail(
        "sendgrid",
        "SendGrid scopes accessible: count=2 scope_hash=0123456789abcdef",
    ) == "scopes/0123456789abcdef"
    assert cloud_validate._validated_identifier_from_detail(
        "mailchimp",
        "Mailchimp ping ok: dc=us1 health=Everything's Chimpy!",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "slack",
        "Slack auth ok: actor_id=U7A3C9K2 team_id=T9B2D6F4",
    ) == "t9b2d6f4/u7a3c9k2"
    assert cloud_validate._validated_identifier_from_detail(
        "discord",
        "Discord bot auth ok: bot_id=739251864203918576 bot_profile_present=true",
    ) == "739251864203918576"
    assert cloud_validate._validated_identifier_from_detail(
        "telegram",
        "Telegram bot auth ok: bot_id=725419863 bot_profile_present=true",
    ) == "725419863"
    assert cloud_validate._validated_identifier_from_detail(
        "cloudflare",
        "Cloudflare token valid: token_id=abcdef1234567890abcdef1234567890 status=active",
    ) == "abcdef1234567890abcdef1234567890"
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user ok: user_id=usr_abcdefghijklmnop user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "vercel",
        "Vercel user ok: user_id=usr_abcdefghijklmnop "
        "user_profile_present=true profile_hash=0123456789abcdef",
    ) == "usr_abcdefghijklmnop"
    assert cloud_validate._validated_identifier_from_detail(
        "netlify",
        "Netlify user ok: user_id=netlify-user-123 user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "netlify",
        "Netlify user ok: user_id=netlify-user-123 "
        "user_profile_present=true profile_hash=0123456789abcdef",
    ) == "netlify-user-123"
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=eu.posthog.com "
        "user_id=018f9b7d-1234-4567-9abc-def012345678 user_profile_present=true",
    ) is None
    assert cloud_validate._validated_identifier_from_detail(
        "posthog",
        "PostHog users me ok: host=eu.posthog.com "
        "user_id=018f9b7d-1234-4567-9abc-def012345678 "
        "user_profile_present=true profile_hash=0123456789abcdef",
    ) == "eu.posthog.com/018f9b7d-1234-4567-9abc-def012345678"
    assert cloud_validate._validated_identifier_from_detail(
        "azure",
        "Azure blob list accessible: account=acmestorage containers=2",
    ) == "acmestorage"
    assert cloud_validate._validated_identifier_from_detail(
        "twilio",
        "Twilio account accessible: sid=AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3 status=active",
    ) == "AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3"
    assert cloud_validate._validated_identifier_from_detail(
        "twilio",
        "Twilio account accessible: sid=AC1234567890abcdef1234567890abcdef status=suspended",
    ) is None
