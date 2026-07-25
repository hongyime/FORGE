from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.phase4 import cloud_validate
from forge.utils.intel import http_pacing


class _FakeResponse:
    def __init__(self, status_code: int, text: str, headers: dict | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "application/json"}


class _FirebaseClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_FirebaseClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "init.json" in url:
            return _FakeResponse(200, '{"projectId":"acme-firebase-prod","appId":"1:test:web"}')
        return _FakeResponse(404, "missing")


class _FirebaseLiveDataClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_FirebaseLiveDataClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "init.json" in url:
            return _FakeResponse(200, '{"projectId":"acme-firebase-prod","appId":"1:test:web"}')
        if "firebaseio.com/users.json" in url:
            return _FakeResponse(200, '{"alice":{"email":"ops@acme.io"}}')
        if "firebaseio.com" in url:
            return _FakeResponse(200, '{"users":true}')
        return _FakeResponse(404, "missing")


class _AwsClientReferenceClient:
    calls: list[str] = []
    kwargs_seen: list[dict] = []

    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AwsClientReferenceClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        forbidden_headers = {"authorization", "x-api-key"}
        headers = {str(key).lower() for key in dict(kwargs.get("headers") or {})}
        assert not any(key in kwargs for key in ("params", "json", "data", "auth"))
        assert not forbidden_headers.intersection(headers)
        self.kwargs_seen.append(dict(kwargs))
        self.calls.append(url)
        if url == "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCd12345/.well-known/openid-configuration":
            return _FakeResponse(
                200,
                json.dumps(
                    {
                        "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCd12345",
                        "jwks_uri": (
                            "https://cognito-idp.us-east-1.amazonaws.com/"
                            "us-east-1_AbCd12345/.well-known/jwks.json"
                        ),
                    }
                ),
            )
        if url == "https://abc123456789.appsync-api.us-east-1.amazonaws.com/graphql":
            return _FakeResponse(
                403,
                '{"errors":[{"message":"Missing Authentication Token"}]}',
                {"content-type": "application/json", "x-amzn-requestid": "req-1"},
            )
        return _FakeResponse(404, "missing", {"content-type": "text/plain"})


class _FirebaseHoneypotClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_FirebaseHoneypotClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del url, kwargs
        return _FakeResponse(
            200,
            (
                '{"projectId":"example-project","appId":"sample-app",'
                '"storageBucket":"localhost","apiKey":"changeme"}'
            ),
        )


class _FirebaseJsonErrorClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_FirebaseJsonErrorClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "firebaseio.com" in url:
            return _FakeResponse(200, '{"error":"Permission denied"}')
        return _FakeResponse(404, "missing")


class _FirebaseMetadataOnlyShallowClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_FirebaseMetadataOnlyShallowClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "init.json" in url:
            return _FakeResponse(200, '{"projectId":"acme-firebase-prod","appId":"1:test:web"}')
        if "firebaseio.com" in url:
            return _FakeResponse(200, '{"rules":true,"settings":true}')
        return _FakeResponse(404, "missing")


class _FirebaseShallowKeyOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_FirebaseShallowKeyOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "init.json" in url:
            return _FakeResponse(200, '{"projectId":"acme-firebase-prod","appId":"1:test:web"}')
        if "firebaseio.com/users.json" in url:
            return _FakeResponse(200, "{}")
        if "firebaseio.com/audit.json" in url:
            return _FakeResponse(403, '{"error":"Permission denied"}')
        if "firebaseio.com" in url:
            return _FakeResponse(200, '{"users":true,"audit":true}')
        return _FakeResponse(404, "missing")


class _SupabaseHoneypotClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_SupabaseHoneypotClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del url, kwargs
        return _FakeResponse(
            200,
            (
                '{"site_url":"https://example.com","uri_allow_list":'
                '["http://localhost:3000","https://demo.example.com"],'
                '"mailer_autoconfirm":false}'
            ),
        )


class _SupabaseJsonErrorClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_SupabaseJsonErrorClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del url, kwargs
        return _FakeResponse(
            200,
            '{"message":"Missing authorization header","code":"PGRST301"}',
        )


class _SupabaseHtmlLandingClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_SupabaseHtmlLandingClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del url, kwargs
        return _FakeResponse(
            200,
            (
                "<!doctype html><html><head><title>Sign in</title></head>"
                "<body>Sign in to continue</body></html>"
            ),
        )


class _SupabaseSettingsOnlySecretClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_SupabaseSettingsOnlySecretClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "auth/v1/settings" in url:
            return _FakeResponse(
                200,
                (
                    '{"site_url":"https://portal.acme.io","external_email_enabled":true,'
                    '"mailer_autoconfirm":false}'
                ),
            )
        return _FakeResponse(
            403,
            '{"message":"Missing authorization header","code":"PGRST301"}',
        )


class _SupabaseRestAccessClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_SupabaseRestAccessClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "auth/v1/settings" in url:
            return _FakeResponse(
                200,
                (
                    '{"site_url":"https://portal.acme.io","external_email_enabled":true,'
                    '"mailer_autoconfirm":false}'
                ),
            )
        return _FakeResponse(
            200,
            '[{"id":1,"email":"ops@acme.io"}]',
        )


class _SupabaseRestLowSignalRowClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_SupabaseRestLowSignalRowClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "auth/v1/settings" in url:
            return _FakeResponse(
                200,
                (
                    '{"site_url":"https://portal.acme.io","external_email_enabled":true,'
                    '"mailer_autoconfirm":false}'
                ),
            )
        return _FakeResponse(
            200,
            (
                '[{"id":1,"created_at":"2026-07-14T00:00:00Z",'
                '"updated_at":"2026-07-14T00:01:00Z","active":true},'
                '{"id":2,"created_at":"2026-07-14T00:02:00Z",'
                '"updated_at":"2026-07-14T00:03:00Z","active":false}]'
            ),
        )


class _SupabaseRestSyntheticRowClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_SupabaseRestSyntheticRowClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "auth/v1/settings" in url:
            return _FakeResponse(
                200,
                (
                    '{"site_url":"https://portal.acme.io","external_email_enabled":true,'
                    '"mailer_autoconfirm":false}'
                ),
            )
        return _FakeResponse(
            200,
            '[{"id":1,"email":"test@example.com","name":"Test User"}]',
        )


class _SupabaseRestReservedExampleRowClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_SupabaseRestReservedExampleRowClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "auth/v1/settings" in url:
            return _FakeResponse(
                200,
                (
                    '{"site_url":"https://portal.acme.io","external_email_enabled":true,'
                    '"mailer_autoconfirm":false}'
                ),
            )
        return _FakeResponse(
            200,
            '[{"id":1,"email":"alice@example.net","name":"Alice Customer"}]',
        )


class _SupabaseRestSchemaOnlySecretClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_SupabaseRestSchemaOnlySecretClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "auth/v1/settings" in url:
            return _FakeResponse(
                200,
                (
                    '{"site_url":"https://portal.acme.io","external_email_enabled":true,'
                    '"mailer_autoconfirm":false}'
                ),
            )
        return _FakeResponse(
            200,
            (
                '{"openapi":"3.0.0","info":{"title":"PostgREST API"},'
                '"paths":{"/rest/v1/users":{"get":{"responses":{"200":{"description":"OK"}}}}}}'
            ),
        )


class _SupabaseRestCatalogOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_SupabaseRestCatalogOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "auth/v1/settings" in url:
            return _FakeResponse(
                200,
                (
                    '{"site_url":"https://portal.acme.io","external_email_enabled":true,'
                    '"mailer_autoconfirm":false}'
                ),
            )
        return _FakeResponse(
            200,
            (
                '[{"schema":"public","name":"users","href":"/rest/v1/users"},'
                '{"schema":"public","name":"events","href":"/rest/v1/events"}]'
            ),
        )


class _MixedBatchClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_MixedBatchClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-firebase-prod" in url and "init.json" in url:
            return _FakeResponse(200, '{"projectId":"acme-firebase-prod","appId":"1:test:web"}')
        if "acme-firebase-prod" in url and "firebaseio.com/users.json" in url:
            return _FakeResponse(200, '{"alice":{"email":"ops@acme.io"}}')
        if "acme-firebase-prod" in url and "firebaseio.com" in url:
            return _FakeResponse(200, '{"users":true}')
        if "acme-workspace.supabase.co" in url:
            return _FakeResponse(
                200,
                (
                    '{"site_url":"https://example.com","uri_allow_list":'
                    '["http://localhost:3000","https://demo.example.com"],'
                    '"mailer_autoconfirm":false}'
                ),
                )
        return _FakeResponse(404, "missing")

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")


class _S3HeadClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3HeadClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>reports/executive-summary.pdf</Key></Contents>"
                    "<Contents><Key>artifacts/mobile/config.json</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3RateLimitThenListClient:
    instances: list["_S3RateLimitThenListClient"] = []

    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs
        self.calls: list[tuple[str, str, dict]] = []
        self._head_responses = [
            _FakeResponse(429, "", headers={"Retry-After": "5"}),
            _FakeResponse(200, ""),
        ]
        self.instances.append(self)

    def __enter__(self) -> "_S3RateLimitThenListClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        self.calls.append(("HEAD", url, dict(kwargs)))
        return self._head_responses.pop(0)

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        self.calls.append(("GET", url, dict(kwargs)))
        return _FakeResponse(
            200,
            (
                "<?xml version='1.0' encoding='UTF-8'?>"
                "<ListBucketResult>"
                "<Contents><Key>reports/executive-summary.pdf</Key></Contents>"
                "</ListBucketResult>"
            ),
        )


class _DOSpacesClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_DOSpacesClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-space-public.nyc3.digitaloceanspaces.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-space-public.nyc3.digitaloceanspaces.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>reports/engagement-summary.pdf</Key></Contents>"
                    "<Contents><Key>artifacts/mobile/config.json</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _DOSpacesStaticSiteScaffoldClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_DOSpacesStaticSiteScaffoldClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-space-public.nyc3.digitaloceanspaces.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-space-public.nyc3.digitaloceanspaces.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>index.html</Key></Contents>"
                    "<Contents><Key>favicon.ico</Key></Contents>"
                    "<Contents><Key>site.webmanifest</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _DOSpacesApiDocumentationOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_DOSpacesApiDocumentationOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-space-public.nyc3.digitaloceanspaces.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-space-public.nyc3.digitaloceanspaces.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>openapi.json</Key></Contents>"
                    "<Contents><Key>docs/graphql/schema.graphql</Key></Contents>"
                    "<Contents><Key>soap/service.wsdl</Key></Contents>"
                    "<Contents><Key>swagger-ui/swagger-ui-bundle.js</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3HoneypotClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3HoneypotClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>sample/example.com/test-data.json</Key></Contents>"
                    "<Contents><Key>placeholder/honeypot-records.txt</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3SingleObjectDecoyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3SingleObjectDecoyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>sample/test-data.json</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3ScaffoldOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3ScaffoldOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>archive/</Key></Contents>"
                    "<Contents><Key>.gitkeep</Key></Contents>"
                    "<Contents><Key>README.md</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3PackageMetadataOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3PackageMetadataOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>services/api/package.json</Key></Contents>"
                    "<Contents><Key>services/api/package-lock.json</Key></Contents>"
                    "<Contents><Key>services/api/pyproject.toml</Key></Contents>"
                    "<Contents><Key>frontend/tsconfig.app.json</Key></Contents>"
                    "<Contents><Key>frontend/vite.config.ts</Key></Contents>"
                    "<Contents><Key>frontend/tailwind.config.js</Key></Contents>"
                    "<Contents><Key>deploy/chart/Chart.yaml</Key></Contents>"
                    "<Contents><Key>deploy/chart/Chart.lock</Key></Contents>"
                    "<Contents><Key>deploy/helmfile.yaml</Key></Contents>"
                    "<Contents><Key>deploy/kustomization.yaml</Key></Contents>"
                    "<Contents><Key>deploy/skaffold.yml</Key></Contents>"
                    "<Contents><Key>deploy/Kptfile</Key></Contents>"
                    "<Contents><Key>docs/CHANGELOG.md</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3RuntimeMetadataOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3RuntimeMetadataOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>.nvmrc</Key></Contents>"
                    "<Contents><Key>services/api/.python-version</Key></Contents>"
                    "<Contents><Key>.tool-versions</Key></Contents>"
                    "<Contents><Key>ruby/.ruby-version</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3FilesystemMetadataOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3FilesystemMetadataOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>exports/.DS_Store</Key></Contents>"
                    "<Contents><Key>media/Thumbs.db</Key></Contents>"
                    "<Contents><Key>desktop.ini</Key></Contents>"
                    "<Contents><Key>__MACOSX/._report.pdf</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3ApiDocumentationOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3ApiDocumentationOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>openapi.json</Key></Contents>"
                    "<Contents><Key>docs/openapi/swagger.yaml</Key></Contents>"
                    "<Contents><Key>docs/graphql/schema.graphql</Key></Contents>"
                    "<Contents><Key>soap/service.wsdl</Key></Contents>"
                    "<Contents><Key>swagger-ui/swagger-ui-bundle.js</Key></Contents>"
                    "<Contents><Key>api-docs/acme.postman_collection.json</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3ApiDocsPlusDataClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3ApiDocsPlusDataClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>openapi.json</Key></Contents>"
                    "<Contents><Key>exports/customer-records.csv</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3StaticSiteScaffoldClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3StaticSiteScaffoldClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>index.html</Key></Contents>"
                    "<Contents><Key>favicon.ico</Key></Contents>"
                    "<Contents><Key>robots.txt</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3PublicMetadataStaticSiteClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3PublicMetadataStaticSiteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>app-ads.txt</Key></Contents>"
                    "<Contents><Key>sellers.json</Key></Contents>"
                    "<Contents><Key>manifest</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3DomainVerificationStaticSiteClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3DomainVerificationStaticSiteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>google1234567890abcdef.html</Key></Contents>"
                    "<Contents><Key>BingSiteAuth.xml</Key></Contents>"
                    "<Contents><Key>yandex_1234567890abcdef.html</Key></Contents>"
                    "<Contents><Key>baidu_verify_1234567890abcdef.html</Key></Contents>"
                    "<Contents><Key>pinterest-1234567890abcdef.html</Key></Contents>"
                    "<Contents><Key>facebook-domain-verification.html</Key></Contents>"
                    "<Contents><Key>.well-known/apple-developer-merchantid-domain-association</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3FrameworkStaticSiteClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3FrameworkStaticSiteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>index.html</Key></Contents>"
                    "<Contents><Key>asset-manifest.json</Key></Contents>"
                    "<Contents><Key>service-worker.js</Key></Contents>"
                    "<Contents><Key>static/js/main.8f3ea4bd.js</Key></Contents>"
                    "<Contents><Key>static/chunks/webpack-3f1a2b.js</Key></Contents>"
                    "<Contents><Key>chunks/framework-41d8c3a2.js</Key></Contents>"
                    "<Contents><Key>static/assets/logo-7bb2d.svg</Key></Contents>"
                    "<Contents><Key>public/build/app-91af22.css</Key></Contents>"
                    "<Contents><Key>_next/static/chunks/app-4b2fe9aa.js</Key></Contents>"
                    "<Contents><Key>favicon-32x32.png</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3HostingConfigStaticSiteClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3HostingConfigStaticSiteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>vercel.json</Key></Contents>"
                    "<Contents><Key>netlify.toml</Key></Contents>"
                    "<Contents><Key>_routes.json</Key></Contents>"
                    "<Contents><Key>build-manifest.json</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3PlainStaticAssetSiteClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3PlainStaticAssetSiteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>css/site.css</Key></Contents>"
                    "<Contents><Key>js/app.js</Key></Contents>"
                    "<Contents><Key>images/logo.svg</Key></Contents>"
                    "<Contents><Key>fonts/inter.woff2</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3WellKnownStaticSiteClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3WellKnownStaticSiteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>.well-known/assetlinks.json</Key></Contents>"
                    "<Contents><Key>.well-known/apple-app-site-association</Key></Contents>"
                    "<Contents><Key>favicon.ico</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3IdentityDiscoveryMetadataClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3IdentityDiscoveryMetadataClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>.well-known/openid-configuration</Key></Contents>"
                    "<Contents><Key>.well-known/jwks.json</Key></Contents>"
                    "<Contents><Key>.well-known/webfinger</Key></Contents>"
                    "<Contents><Key>.well-known/mta-sts.txt</Key></Contents>"
                    "<Contents><Key>.well-known/did.json</Key></Contents>"
                    "<Contents><Key>.well-known/matrix/server</Key></Contents>"
                    "<Contents><Key>.well-known/change-password</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3WellKnownChallengeStaticSiteClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3WellKnownChallengeStaticSiteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>.well-known/acme-challenge/a1b2c3d4</Key></Contents>"
                    "<Contents><Key>.well-known/pki-validation/fileauth.txt</Key></Contents>"
                    "<Contents><Key>_worker.js</Key></Contents>"
                    "<Contents><Key>CNAME</Key></Contents>"
                    "<Contents><Key>firebase.json</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3MarketingPageStaticSiteClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3MarketingPageStaticSiteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>about.html</Key></Contents>"
                    "<Contents><Key>contact.html</Key></Contents>"
                    "<Contents><Key>privacy-policy.html</Key></Contents>"
                    "<Contents><Key>terms-of-service.html</Key></Contents>"
                    "<Contents><Key>llms.txt</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3SitemapFeedStaticSiteClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3SitemapFeedStaticSiteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>sitemap_index.xml</Key></Contents>"
                    "<Contents><Key>post-sitemap.xml</Key></Contents>"
                    "<Contents><Key>feed.xml</Key></Contents>"
                    "<Contents><Key>rss.xml</Key></Contents>"
                    "<Contents><Key>atom.xml</Key></Contents>"
                    "<Contents><Key>apple-touch-icon-precomposed.png</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3StructuredErrorClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3StructuredErrorClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<Error><Code>InvalidRequest</Code>"
                    "<Message>Bad request for bucket listing.</Message></Error>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3ForbiddenNoSuchBucketClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3ForbiddenNoSuchBucketClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(
                403,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<Error><Code>NoSuchBucket</Code>"
                    "<Message>The specified bucket does not exist.</Message></Error>"
                ),
            )
        return _FakeResponse(404, "missing")


class _S3HeadOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3HeadOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del url, kwargs
        raise cloud_validate.httpx.ReadTimeout("listing unavailable")


class _S3UnexpectedSuccessPayloadClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_S3UnexpectedSuccessPayloadClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, "")
        return _FakeResponse(404, "missing")

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acme-public-assets.s3.amazonaws.com" in url:
            return _FakeResponse(200, '{"status":"ok","bucket":"acme-public-assets"}')
        return _FakeResponse(404, "missing")


class _GCSClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>reports/summary.pdf</Key></Contents>"
                    "<Contents><Key>mobile/config.json</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSUnexpectedSuccessPayloadClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSUnexpectedSuccessPayloadClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(200, '{"status":"ok","bucket":"acme-gcs-public"}')
        return _FakeResponse(404, "missing")


class _GCSJsonListingClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSJsonListingClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                json.dumps(
                    {
                        "kind": "storage#objects",
                        "items": [
                            {
                                "kind": "storage#object",
                                "bucket": "acme-gcs-public",
                                "name": "exports/customer-data.csv",
                                "size": "2048",
                            },
                            {
                                "kind": "storage#object",
                                "bucket": "acme-gcs-public",
                                "name": "mobile/config.json",
                                "contentType": "application/json",
                            },
                        ],
                    }
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSJsonMetadataOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSJsonMetadataOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                json.dumps(
                    {
                        "kind": "storage#objects",
                        "items": [
                            {
                                "kind": "storage#object",
                                "bucket": "acme-gcs-public",
                                "name": "package.json",
                            },
                            {
                                "kind": "storage#object",
                                "bucket": "acme-gcs-public",
                                "name": "README.md",
                            },
                            {
                                "kind": "storage#object",
                                "bucket": "acme-gcs-public",
                                "name": "frontend/vite.config.ts",
                            },
                            {
                                "kind": "storage#object",
                                "bucket": "acme-gcs-public",
                                "name": "frontend/tailwind.config.js",
                            },
                        ],
                    }
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSApiDocumentationOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSApiDocumentationOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>openapi.json</Key></Contents>"
                    "<Contents><Key>docs/graphql/schema.graphql</Key></Contents>"
                    "<Contents><Key>soap/service.wsdl</Key></Contents>"
                    "<Contents><Key>swagger-ui/swagger-ui-bundle.js</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSJsonApiDocumentationOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSJsonApiDocumentationOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                json.dumps(
                    {
                        "kind": "storage#objects",
                        "items": [
                            {"kind": "storage#object", "name": "openapi.json"},
                            {"kind": "storage#object", "name": "docs/graphql/schema.graphql"},
                            {"kind": "storage#object", "name": "soap/service.wsdl"},
                            {
                                "kind": "storage#object",
                                "name": "swagger-ui/swagger-ui-bundle.js",
                            },
                        ],
                    }
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSJsonSingleObjectDecoyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSJsonSingleObjectDecoyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                json.dumps(
                    {
                        "kind": "storage#objects",
                        "items": [
                            {
                                "kind": "storage#object",
                                "bucket": "acme-gcs-public",
                                "name": "sample/test-data.json",
                            }
                        ],
                    }
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSSingleObjectDecoyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSSingleObjectDecoyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>demo/example.com/users.json</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSScaffoldOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSScaffoldOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>reports/</Key></Contents>"
                    "<Contents><Key>.gitkeep</Key></Contents>"
                    "<Contents><Key>README.md</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSPackageMetadataOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSPackageMetadataOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>packages/web/package.json</Key></Contents>"
                    "<Contents><Key>packages/web/pnpm-lock.yaml</Key></Contents>"
                    "<Contents><Key>packages/web/tsconfig.app.json</Key></Contents>"
                    "<Contents><Key>packages/web/vite.config.ts</Key></Contents>"
                    "<Contents><Key>rust/Cargo.toml</Key></Contents>"
                    "<Contents><Key>rust/Cargo.lock</Key></Contents>"
                    "<Contents><Key>deploy/chart/Chart.yaml</Key></Contents>"
                    "<Contents><Key>deploy/helmfile.yaml</Key></Contents>"
                    "<Contents><Key>deploy/kustomization.yaml</Key></Contents>"
                    "<Contents><Key>deploy/skaffold.yml</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSFilesystemMetadataOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSFilesystemMetadataOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>exports/.DS_Store</Key></Contents>"
                    "<Contents><Key>media/Thumbs.db</Key></Contents>"
                    "<Contents><Key>desktop.ini</Key></Contents>"
                    "<Contents><Key>__MACOSX/._report.pdf</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSStaticSiteScaffoldClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSStaticSiteScaffoldClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>index.html</Key></Contents>"
                    "<Contents><Key>favicon.ico</Key></Contents>"
                    "<Contents><Key>security.txt</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSWellKnownChallengeStaticSiteClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSWellKnownChallengeStaticSiteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<ListBucketResult>"
                    "<Contents><Key>.well-known/acme-challenge/a1b2c3d4</Key></Contents>"
                    "<Contents><Key>.well-known/pki-validation/fileauth.txt</Key></Contents>"
                    "<Contents><Key>_worker.js</Key></Contents>"
                    "<Contents><Key>CNAME</Key></Contents>"
                    "<Contents><Key>firebase.json</Key></Contents>"
                    "</ListBucketResult>"
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSHtmlLandingClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSHtmlLandingClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                (
                    "<!doctype html><html><head><title>Access denied</title></head>"
                    "<body>Access denied</body></html>"
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSErrorXmlClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSErrorXmlClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='UTF-8'?>"
                    "<Error><Code>AccessDenied</Code>"
                    "<Message>Access denied.</Message></Error>"
                ),
            )
        return _FakeResponse(404, "missing")


class _GCSForbiddenNotFoundJsonClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_GCSForbiddenNotFoundJsonClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "storage.googleapis.com/acme-gcs-public" in url:
            return _FakeResponse(
                403,
                json.dumps(
                    {
                        "error": {
                            "code": 403,
                            "message": "The specified bucket does not exist.",
                            "status": "NOT_FOUND",
                        }
                    }
                ),
            )
        return _FakeResponse(404, "missing")


class _AzureBlobClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AzureBlobClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acmeblob.blob.core.windows.net/public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='utf-8'?>"
                    "<EnumerationResults>"
                    "<Blobs>"
                    "<Blob><Name>reports/final.json</Name></Blob>"
                    "<Blob><Name>exports/briefing.csv</Name></Blob>"
                    "</Blobs>"
                    "</EnumerationResults>"
                ),
            )
        return _FakeResponse(404, "missing")


class _AzureBlobUnexpectedSuccessPayloadClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AzureBlobUnexpectedSuccessPayloadClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acmeblob.blob.core.windows.net/public" in url:
            return _FakeResponse(200, '{"status":"ok","container":"public"}')
        return _FakeResponse(404, "missing")


class _AzureBlobSingleObjectDecoyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AzureBlobSingleObjectDecoyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acmeblob.blob.core.windows.net/public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='utf-8'?>"
                    "<EnumerationResults>"
                    "<Blobs>"
                    "<Blob><Name>placeholder/test-data.csv</Name></Blob>"
                    "</Blobs>"
                    "</EnumerationResults>"
                ),
            )
        return _FakeResponse(404, "missing")


class _AzureBlobScaffoldOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AzureBlobScaffoldOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acmeblob.blob.core.windows.net/public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='utf-8'?>"
                    "<EnumerationResults>"
                    "<Blobs>"
                    "<Blob><Name>staging/</Name></Blob>"
                    "<Blob><Name>.keep</Name></Blob>"
                    "<Blob><Name>README.txt</Name></Blob>"
                    "</Blobs>"
                    "</EnumerationResults>"
                ),
            )
        return _FakeResponse(404, "missing")


class _AzureBlobPackageMetadataOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AzureBlobPackageMetadataOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acmeblob.blob.core.windows.net/public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='utf-8'?>"
                    "<EnumerationResults>"
                    "<Blobs>"
                    "<Blob><Name>go/go.mod</Name></Blob>"
                    "<Blob><Name>go/go.sum</Name></Blob>"
                    "<Blob><Name>java/pom.xml</Name></Blob>"
                    "<Blob><Name>frontend/tsconfig.app.json</Name></Blob>"
                    "<Blob><Name>frontend/postcss.config.cjs</Name></Blob>"
                    "<Blob><Name>ruby/Gemfile.lock</Name></Blob>"
                    "<Blob><Name>deploy/chart/Chart.yaml</Name></Blob>"
                    "<Blob><Name>deploy/chart/Chart.lock</Name></Blob>"
                    "<Blob><Name>deploy/helmfile.yaml</Name></Blob>"
                    "<Blob><Name>deploy/kustomization.yaml</Name></Blob>"
                    "<Blob><Name>deploy/skaffold.yml</Name></Blob>"
                    "</Blobs>"
                    "</EnumerationResults>"
                ),
            )
        return _FakeResponse(404, "missing")


class _AzureBlobFilesystemMetadataOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AzureBlobFilesystemMetadataOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acmeblob.blob.core.windows.net/public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='utf-8'?>"
                    "<EnumerationResults>"
                    "<Blobs>"
                    "<Blob><Name>exports/.DS_Store</Name></Blob>"
                    "<Blob><Name>media/Thumbs.db</Name></Blob>"
                    "<Blob><Name>desktop.ini</Name></Blob>"
                    "<Blob><Name>__MACOSX/._report.pdf</Name></Blob>"
                    "</Blobs>"
                    "</EnumerationResults>"
                ),
            )
        return _FakeResponse(404, "missing")


class _AzureBlobApiDocumentationOnlyClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AzureBlobApiDocumentationOnlyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acmeblob.blob.core.windows.net/public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='utf-8'?>"
                    "<EnumerationResults>"
                    "<Blobs>"
                    "<Blob><Name>openapi.json</Name></Blob>"
                    "<Blob><Name>docs/graphql/schema.graphql</Name></Blob>"
                    "<Blob><Name>soap/service.wsdl</Name></Blob>"
                    "<Blob><Name>swagger-ui/swagger-ui-bundle.js</Name></Blob>"
                    "</Blobs>"
                    "</EnumerationResults>"
                ),
            )
        return _FakeResponse(404, "missing")


class _AzureBlobStaticSiteScaffoldClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AzureBlobStaticSiteScaffoldClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acmeblob.blob.core.windows.net/public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='utf-8'?>"
                    "<EnumerationResults>"
                    "<Blobs>"
                    "<Blob><Name>index.html</Name></Blob>"
                    "<Blob><Name>favicon.ico</Name></Blob>"
                    "<Blob><Name>sitemap.xml</Name></Blob>"
                    "</Blobs>"
                    "</EnumerationResults>"
                ),
            )
        return _FakeResponse(404, "missing")


class _AzureBlobWellKnownChallengeStaticSiteClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AzureBlobWellKnownChallengeStaticSiteClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acmeblob.blob.core.windows.net/public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='utf-8'?>"
                    "<EnumerationResults>"
                    "<Blobs>"
                    "<Blob><Name>.well-known/acme-challenge/a1b2c3d4</Name></Blob>"
                    "<Blob><Name>.well-known/pki-validation/fileauth.txt</Name></Blob>"
                    "<Blob><Name>_worker.js</Name></Blob>"
                    "<Blob><Name>CNAME</Name></Blob>"
                    "<Blob><Name>firebase.json</Name></Blob>"
                    "</Blobs>"
                    "</EnumerationResults>"
                ),
            )
        return _FakeResponse(404, "missing")


class _AzureBlobErrorXmlClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AzureBlobErrorXmlClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acmeblob.blob.core.windows.net/public" in url:
            return _FakeResponse(
                200,
                (
                    "<?xml version='1.0' encoding='utf-8'?>"
                    "<Error><Code>ContainerNotFound</Code>"
                    "<Message>The specified container does not exist.</Message></Error>"
                ),
            )
        return _FakeResponse(404, "missing")


class _AzureBlobConflictNotFoundClient:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        del args, kwargs

    def __enter__(self) -> "_AzureBlobConflictNotFoundClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
        del kwargs
        if "acmeblob.blob.core.windows.net/public" in url:
            return _FakeResponse(
                409,
                (
                    "<?xml version='1.0' encoding='utf-8'?>"
                    "<Error><Code>ContainerNotFound</Code>"
                    "<Message>The specified container does not exist.</Message></Error>"
                ),
            )
        return _FakeResponse(404, "missing")


def _bootstrap_db(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()


def test_sweep_pending_cloud_validations_processes_validatable_stripe_secret_key_rows_without_cloud_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (8, 1001, '', 'stripe', 'stripe_live_secret_key', 'artifact',
                 '', 'config.py', 'sk_live_...1234', 'ciphertext-placeholder', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "sk_live_fakekey12345678901234567890",
    )
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        StripeKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        StripeKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "Stripe balance accessible: mode=live currencies=sgd,usd "
                "balances=available:1,pending:1"
            ),
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["key_id"] == 8
    assert summary["results"][0]["validation_status"] == "VALIDATED"
    assert summary["results"][0]["validation_method"] == "stripe_balance_api"
    assert summary["results"][0]["identifier"] == "live/sgd,usd"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("stripe", "live/sgd,usd", "VALIDATED", "stripe_balance_api")

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=8
            """
        ).fetchone()
        assert key_row[0] == "ACTIVE"
        assert str(key_row[1] or "").startswith("VALIDATED:stripe_balance_api:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == [
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed stripe credential reference",
            )
        ]
    finally:
        con.close()


@pytest.mark.parametrize(
    "validation_detail",
    [
        (
            "Stripe balance accessible: mode=live currencies=none "
            "balances=available:0,pending:0"
        ),
        "Stripe balance accessible: mode=live currencies=usd",
    ],
)
def test_sweep_pending_cloud_validations_downgrades_stripe_low_signal_balance_proof(
    tmp_path: Path,
    monkeypatch,
    validation_detail: str,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (9, 1001, '', 'stripe', 'stripe_live_secret_key', 'artifact',
                 '', 'stripe-empty-balance.env', 'sk_live_...1234', 'ciphertext-stripe-empty', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "sk_live_fakekey12345678901234567890",
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        StripeKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        StripeKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=validation_detail,
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 1}
    assert summary["results"][0]["key_id"] == 9
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["identifier"] == "stripe-empty-balance.env"
    assert summary["results"][0]["validation_method"] == "stripe_balance_api"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "stripe",
            "stripe-empty-balance.env",
            "UNVERIFIED",
            "stripe_balance_api",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=9
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith("UNVERIFIED:stripe_balance_api:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_stripe_secret_mode_mismatch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (10, 1001, '', 'stripe', 'stripe_live_secret_key', 'artifact',
                 '', 'stripe-mode.env', 'sk_live_...1234', 'ciphertext-stripe-mode', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "sk_live_fakekey12345678901234567890",
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        StripeKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        StripeKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "Stripe balance accessible: mode=test currencies=usd "
                "balances=available:1,pending:0"
            ),
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 1}
    assert summary["results"][0]["key_id"] == 10
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["identifier"] == "stripe-mode.env"
    assert summary["results"][0]["validation_method"] == "stripe_balance_api"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "stripe",
            "stripe-mode.env",
            "UNVERIFIED",
            "stripe_balance_api",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=10
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith("UNVERIFIED:stripe_balance_api:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_scope_checker_skips_denied_key_rows(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (?, 1001, ?, 'stripe', 'stripe_live_secret_key', 'crawler', ?, 'webapp', 'sk_live_...1234', 'ciphertext-placeholder', 'UNCONFIRMED')
            """,
            [
                (81, "acme.example", "https://app.acme.example/config.js"),
                (82, "evil.example", "https://evil.example/config.js"),
            ],
        )
        con.commit()
    finally:
        con.close()

    validated_key_ids: list[int] = []
    denied_callbacks: list[tuple[int, str]] = []

    def _fake_validate_key_row_payload(row_payload, **kwargs):  # noqa: ANN001
        del kwargs
        key_id = int(row_payload["id"])
        validated_key_ids.append(key_id)
        return (
            key_id,
            int(row_payload["engagement_id"]),
            cloud_validate.CloudValidationResult(
                asset_type="stripe",
                identifier="live/sgd,usd",
                validation_status="VALIDATED",
                validation_method="stripe_balance_api",
                evidence="Stripe balance accessible",
                notes="Stripe balance accessible: mode=live currencies=sgd,usd balances=available:1,pending:1",
            ),
        )

    monkeypatch.setattr(cloud_validate, "_validate_key_row_payload", _fake_validate_key_row_payload)

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
        key_scope_checker=lambda row_payload: int(row_payload["id"]) == 81,
        key_scope_denied_callback=lambda row_payload, reason: denied_callbacks.append(
            (int(row_payload["id"]), reason)
        ),
    )

    assert validated_key_ids == [81]
    assert denied_callbacks == [(82, "scope_manifest_denied")]
    assert summary["attempted"] == 2
    assert summary["succeeded"] == 2
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["status_counts"]["UNVERIFIED"] == 1

    con = sqlite3.connect(db_path)
    try:
        key_rows = {
            int(row[0]): (str(row[1]), str(row[2] or ""))
            for row in con.execute(
                """
                SELECT id, validation_state, validation_detail
                FROM key_scanner_findings
                WHERE id IN (81, 82)
                ORDER BY id
                """
            ).fetchall()
        }
        assert key_rows[81][0] == "ACTIVE"
        assert key_rows[82][0] == "UNCONFIRMED"
        assert key_rows[82][1].startswith("UNVERIFIED:scope_manifest:scope_manifest_denied")

        denied_validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method, evidence, notes
            FROM cloud_validation_results
            WHERE engagement_id=1001 AND asset_type='stripe' AND identifier='https://evil.example/config.js'
            """
        ).fetchone()
        assert denied_validation_row == (
            "stripe",
            "https://evil.example/config.js",
            "UNVERIFIED",
            "scope_manifest",
            "scope denied before key validation",
            "scope_manifest_denied",
        )
    finally:
        con.close()


def test_sweep_pending_cloud_validations_parallelizes_scope_gate_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (?, 1001, ?, 'stripe', 'stripe_live_secret_key', 'crawler', ?, 'webapp', 'sk_live_...1234', 'ciphertext-placeholder', 'UNCONFIRMED')
            """,
            [
                (91, "one.acme.example", "https://one.acme.example/config.js"),
                (92, "two.acme.example", "https://two.acme.example/config.js"),
                (93, "three.acme.example", "https://three.acme.example/config.js"),
                (94, "four.acme.example", "https://four.acme.example/config.js"),
            ],
        )
        con.commit()
    finally:
        con.close()

    active_scope_checks = 0
    max_active_scope_checks = 0
    active_lock = threading.Lock()
    denied_callbacks: list[tuple[int, str]] = []

    def _scope_checker(row_payload: dict[str, object]) -> bool:
        nonlocal active_scope_checks, max_active_scope_checks
        with active_lock:
            active_scope_checks += 1
            max_active_scope_checks = max(max_active_scope_checks, active_scope_checks)
        time.sleep(0.05)
        with active_lock:
            active_scope_checks -= 1
        return int(row_payload["id"]) in {91, 93}

    def _fake_validate_key_row_payload(row_payload, **kwargs):  # noqa: ANN001
        del kwargs
        key_id = int(row_payload["id"])
        return (
            key_id,
            int(row_payload["engagement_id"]),
            cloud_validate.CloudValidationResult(
                asset_type="stripe",
                identifier=f"live/{key_id}",
                validation_status="VALIDATED",
                validation_method="stripe_balance_api",
                evidence=f"Stripe balance accessible for {key_id}",
                notes=f"Stripe proof for {key_id}",
            ),
        )

    monkeypatch.setattr(cloud_validate, "_validate_key_row_payload", _fake_validate_key_row_payload)

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=4,
        key_scope_checker=_scope_checker,
        key_scope_denied_callback=lambda row_payload, reason: denied_callbacks.append(
            (int(row_payload["id"]), reason)
        ),
    )

    assert max_active_scope_checks > 1
    assert denied_callbacks == [(92, "scope_manifest_denied"), (94, "scope_manifest_denied")]
    assert summary["attempted"] == 4
    assert summary["succeeded"] == 4
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 2
    assert summary["status_counts"]["UNVERIFIED"] == 2
    assert [result["key_id"] for result in summary["results"]] == [92, 94, 91, 93]

    con = sqlite3.connect(db_path)
    try:
        states = {
            int(row[0]): str(row[1])
            for row in con.execute(
                """
                SELECT id, validation_state
                FROM key_scanner_findings
                WHERE id IN (91, 92, 93, 94)
                ORDER BY id
                """
            ).fetchall()
        }
        assert states == {
            91: "ACTIVE",
            92: "UNCONFIRMED",
            93: "ACTIVE",
            94: "UNCONFIRMED",
        }
    finally:
        con.close()


def test_sweep_pending_cloud_validations_processes_validatable_github_pat_rows_without_cloud_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (28, 1001, '', 'github', 'github_pat_classic', 'artifact',
                 'https://github.com/example/repo/blob/main/.env', 'example/repo', 'ghp_...1234', 'ciphertext-github', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "ghp_fakevalidatedtoken123456789012345678",
    )
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        GithubPatValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        GithubPatValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "GitHub user ok: user_id=738251 login=acmebot user_profile_present=true "
                "profile_url_matches_login=true"
            ),
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["key_id"] == 28
    assert summary["results"][0]["validation_status"] == "VALIDATED"
    assert summary["results"][0]["validation_method"] == "github_user_api"
    assert summary["results"][0]["identifier"] == "acmebot"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("github", "acmebot", "VALIDATED", "github_user_api")

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=28
            """
        ).fetchone()
        assert key_row[0] == "ACTIVE"
        assert str(key_row[1] or "").startswith("VALIDATED:github_user_api:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == [
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed github credential reference",
            )
        ]
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_handle_provider_active_results_without_stable_proof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES (?, 1001, '', ?, ?, 'artifact', ?, ?, ?, ?, 'UNCONFIRMED')
            """,
            [
                (
                    29,
                    "github",
                    "github_pat_classic",
                    "https://github.com/example/repo/blob/main/.env",
                    "example/repo",
                    "ghp_...AAAA",
                    "ciphertext-github-low-signal",
                ),
                (
                    42,
                    "gitlab",
                    "gitlab_pat",
                    "",
                    "gitlab.env",
                    "glpa...BBBB",
                    "ciphertext-gitlab-low-signal",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    def _fake_decrypt(value: str) -> str:
        if value == "ciphertext-github-low-signal":
            return "ghp_fakevalidatedtoken123456789012345678"
        if value == "ciphertext-gitlab-low-signal":
            return "glpat-" + "Y" * 20
        return value

    monkeypatch.setattr(cloud_validate, "_decrypt_secret", _fake_decrypt)
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        GithubPatValidator,
        GitlabPatValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        GithubPatValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="GitHub user ok: user_id=738251 login=testuser user_profile_present=true",
        ),
    )
    monkeypatch.setattr(
        GitlabPatValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="GitLab user ok: user_id=739251 username=delta-ops user_profile_present=true",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 2
    assert summary["succeeded"] == 2
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 2}

    results_by_service = {str(row["asset_type"]): row for row in summary["results"]}
    assert results_by_service["github"]["validation_method"] == "github_user_api"
    assert results_by_service["gitlab"]["validation_method"] == "gitlab_current_user_api"
    assert {
        str(row["validation_status"])
        for row in results_by_service.values()
    } == {"UNVERIFIED"}

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY asset_type
            """
        ).fetchall()
        assert validation_rows == [
            ("github", "UNVERIFIED", "github_user_api"),
            ("gitlab", "UNVERIFIED", "gitlab_current_user_api"),
        ]

        key_rows = con.execute(
            """
            SELECT service, validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id IN (29, 42)
            ORDER BY service
            """
        ).fetchall()
        assert [(row[0], row[1]) for row in key_rows] == [
            ("github", "UNCONFIRMED"),
            ("gitlab", "UNCONFIRMED"),
        ]
        assert all(str(row[2] or "").startswith("UNVERIFIED:") for row in key_rows)

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY title
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_processes_validatable_sendgrid_key_rows_without_cloud_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (29, 1001, '', 'sendgrid', 'sendgrid_api_key', 'artifact',
                 '', 'mailer.env', 'SG...1234', 'ciphertext-sendgrid', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg",
    )
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        SendgridKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        SendgridKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "SendGrid profile ok: proof=profile profile_hash=0123456789abcdef "
                "email_present=true username_present=true"
            ),
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["key_id"] == 29
    assert summary["results"][0]["validation_status"] == "VALIDATED"
    assert summary["results"][0]["validation_method"] == "sendgrid_profile_api"
    assert summary["results"][0]["identifier"] == "profile/0123456789abcdef"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "sendgrid",
            "profile/0123456789abcdef",
            "VALIDATED",
            "sendgrid_profile_api",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=29
            """
        ).fetchone()
        assert key_row[0] == "ACTIVE"
        assert str(key_row[1] or "").startswith("VALIDATED:sendgrid_profile_api:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == [
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed sendgrid credential reference",
            )
        ]
    finally:
        con.close()


def test_sweep_pending_cloud_validations_uses_sendgrid_profile_identifier_without_account_pii(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (39, 1001, '', 'sendgrid', 'sendgrid_api_key', 'artifact',
                 '', 'mailer.env', 'SG...9999', 'ciphertext-sendgrid-username', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg",
    )
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        SendgridKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        SendgridKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "SendGrid profile ok: proof=profile profile_hash=a46fcd8c3e0c7780 "
                "username_present=true"
            ),
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["key_id"] == 39
    assert summary["results"][0]["identifier"] == "profile/a46fcd8c3e0c7780"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "sendgrid",
            "profile/a46fcd8c3e0c7780",
            "VALIDATED",
            "sendgrid_profile_api",
        )
    finally:
        con.close()


def test_sweep_pending_cloud_validations_uses_sendgrid_scope_hash_identifier(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (63, 1001, '', 'sendgrid', 'sendgrid_api_key', 'artifact',
                 '', 'mailer-scopes.env', 'SG...7777', 'ciphertext-sendgrid-scopes', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg",
    )
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        SendgridKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        SendgridKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="SendGrid scopes accessible: count=3 scope_hash=fedcba9876543210",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["identifier"] == "scopes/fedcba9876543210"
    assert summary["results"][0]["validation_method"] == "sendgrid_profile_api"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "sendgrid",
            "scopes/fedcba9876543210",
            "VALIDATED",
            "sendgrid_profile_api",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=63
            """
        ).fetchone()
        assert key_row[0] == "ACTIVE"
        assert str(key_row[1] or "").startswith("VALIDATED:sendgrid_profile_api:")
    finally:
        con.close()


def test_sweep_pending_cloud_validations_records_google_model_list_as_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (40, 1001, '', 'google', 'google_api_key', 'artifact',
                 '', 'web-config.env', 'AIza...ZZZZ', 'ciphertext-google', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "AIza" + "Z" * 35,
    )
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        GoogleApiKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        GoogleApiKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "Google Generative Language models ok: models=2 "
                "sample=models/gemini-2.5-flash,models/text-embedding-004"
            ),
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["UNVERIFIED"] == 1
    assert summary["results"][0]["key_id"] == 40
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["validation_method"] == "google_generative_language_models_list"
    assert summary["results"][0]["identifier"] == "web-config.env"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "google",
            "web-config.env",
            "UNVERIFIED",
            "google_generative_language_models_list",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=40
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith(
            "UNVERIFIED:google_generative_language_models_list:"
        )

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_records_openai_model_list_as_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (42, 1001, '', 'openai', 'openai_project_api_key', 'artifact',
                 '', 'ai-config.env', 'sk-p...ZZZZ', 'ciphertext-openai', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "sk-proj-" + "Z" * 48,
    )
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        OpenAIKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        OpenAIKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="OpenAI models ok: models=2 sample=gpt-4o-mini,text-embedding-3-small",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["UNVERIFIED"] == 1
    assert summary["results"][0]["key_id"] == 42
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["validation_method"] == "openai_models_list"
    assert summary["results"][0]["identifier"] == "ai-config.env"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "openai",
            "ai-config.env",
            "UNVERIFIED",
            "openai_models_list",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=42
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith("UNVERIFIED:openai_models_list:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_records_anthropic_model_list_as_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (43, 1001, '', 'anthropic', 'anthropic_api_key', 'artifact',
                 '', 'claude.env', 'sk-a...YYYY', 'ciphertext-anthropic', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "sk-ant-api03-" + "Y" * 48,
    )
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AnthropicKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        AnthropicKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Anthropic models ok: models=2 sample=claude-sonnet-4-5,claude-haiku-4-5",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["UNVERIFIED"] == 1
    assert summary["results"][0]["key_id"] == 43
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["validation_method"] == "anthropic_models_list"
    assert summary["results"][0]["identifier"] == "claude.env"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "anthropic",
            "claude.env",
            "UNVERIFIED",
            "anthropic_models_list",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=43
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith("UNVERIFIED:anthropic_models_list:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_model_list_proof_without_provider_family(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES (?, 1001, '', ?, ?, 'artifact', '', ?, ?, ?, 'UNCONFIRMED')
            """,
            [
                (
                    44,
                    "openai",
                    "openai_project_api_key",
                    "ai-config.env",
                    "sk-p...MMMM",
                    "ciphertext-openai-arbitrary",
                ),
                (
                    45,
                    "anthropic",
                    "anthropic_api_key",
                    "claude.env",
                    "sk-a...NNNN",
                    "ciphertext-anthropic-arbitrary",
                ),
                (
                    46,
                    "google",
                    "google_api_key",
                    "google.env",
                    "AIza...GGGG",
                    "ciphertext-google-arbitrary",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    def _fake_decrypt(value: str) -> str:
        if "anthropic" in value:
            return "sk-ant-api03-" + "N" * 48
        if "google" in value:
            return "AIza" + "G" * 35
        return "sk-proj-" + "M" * 48

    monkeypatch.setattr(cloud_validate, "_decrypt_secret", _fake_decrypt)
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AnthropicKeyValidator,
        GoogleApiKeyValidator,
        OpenAIKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        OpenAIKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="OpenAI models ok: models=1 sample=vendor-model-alpha",
        ),
    )
    monkeypatch.setattr(
        AnthropicKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Anthropic models ok: models=1 sample=sonnet-placeholder-2026",
        ),
    )
    monkeypatch.setattr(
        GoogleApiKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Google Generative Language models ok: models=1 sample=models/vendor-model-alpha",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 3
    assert summary["succeeded"] == 3
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 3}
    assert {row["validation_status"] for row in summary["results"]} == {"UNVERIFIED"}

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY asset_type
            """
        ).fetchall()
        assert validation_rows == [
            ("anthropic", "claude.env", "UNVERIFIED", "anthropic_models_list"),
            ("google", "google.env", "UNVERIFIED", "google_generative_language_models_list"),
            ("openai", "ai-config.env", "UNVERIFIED", "openai_models_list"),
        ]

        key_rows = con.execute(
            """
            SELECT service, validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id IN (44, 45, 46)
            ORDER BY service
            """
        ).fetchall()
        assert [(row[0], row[1]) for row in key_rows] == [
            ("anthropic", "UNCONFIRMED"),
            ("google", "UNCONFIRMED"),
            ("openai", "UNCONFIRMED"),
        ]
        assert all(str(row[2] or "").startswith("UNVERIFIED:") for row in key_rows)

        findings = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert findings == 0
    finally:
        con.close()


def test_sweep_pending_cloud_validations_processes_social_messaging_and_collaboration_provider_tokens_without_cloud_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES (?, 1001, '', ?, ?, 'artifact', '', ?, ?, ?, 'UNCONFIRMED')
            """,
            [
                (
                    44,
                    "huggingface",
                    "huggingface_token",
                    "ml.env",
                    "hf_A...HHHH",
                    "ciphertext-huggingface",
                ),
                (
                    45,
                    "discord",
                    "discord_bot_token",
                    "chat.env",
                    "MMMM...BBBB",
                    "ciphertext-discord",
                ),
                (
                    46,
                    "telegram",
                    "telegram_bot_token",
                    "bot.env",
                    "1234...TTTT",
                    "ciphertext-telegram",
                ),
                (
                    47,
                    "notion",
                    "notion_integration_token",
                    "workspace.env",
                    "ntn_...NNNN",
                    "ciphertext-notion",
                ),
                (
                    48,
                    "datadog",
                    "datadog_api_key",
                    "observability.env",
                    "0123...cdef",
                    "ciphertext-datadog",
                ),
                (
                    49,
                    "cloudflare",
                    "cloudflare_api_token",
                    "edge.env",
                    "CCCC...CCCC",
                    "ciphertext-cloudflare",
                ),
                (
                    50,
                    "vercel",
                    "vercel_access_token",
                    "deploy.env",
                    "VVVV...VVVV",
                    "ciphertext-vercel",
                ),
                (
                    51,
                    "netlify",
                    "netlify_personal_access_token",
                    "static.env",
                    "NNNN...NNNN",
                    "ciphertext-netlify",
                ),
                (
                    52,
                    "posthog",
                    "posthog_personal_api_key",
                    "analytics.env",
                    "phx_...PPPP",
                    "ciphertext-posthog",
                ),
                (
                    53,
                    "sentry",
                    "sentry_auth_token",
                    "errors.env",
                    "SSSS...SSSS",
                    "ciphertext-sentry",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    def _fake_decrypt(value: str) -> str:
        if value == "ciphertext-huggingface":
            return "hf_" + "H" * 36
        if value == "ciphertext-discord":
            return "NzM5MjUxODY0MjAzOTE4NTc2.AAAAAA." + "B" * 27
        if value == "ciphertext-telegram":
            return "725419863:" + "T" * 35
        if value == "ciphertext-notion":
            return "ntn_" + "N" * 40
        if value == "ciphertext-datadog":
            return "0123456789abcdef0123456789abcdef"
        if value == "ciphertext-cloudflare":
            return "C" * 40
        if value == "ciphertext-vercel":
            return "V" * 40
        if value == "ciphertext-netlify":
            return "N" * 40
        if value == "ciphertext-posthog":
            return "phx_" + "P" * 40
        if value == "ciphertext-sentry":
            return "S" * 40
        return value

    monkeypatch.setattr(cloud_validate, "_decrypt_secret", _fake_decrypt)
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        CloudflareApiTokenValidator,
        DatadogApiKeyValidator,
        DiscordBotTokenValidator,
        HuggingFaceTokenValidator,
        NetlifyTokenValidator,
        NotionTokenValidator,
        PostHogPersonalApiKeyValidator,
        SentryAuthTokenValidator,
        TelegramBotTokenValidator,
        ValidationResult,
        ValidationState,
        VercelTokenValidator,
    )

    monkeypatch.setattr(
        HuggingFaceTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "Hugging Face auth ok: user=acme-mlops "
                "user_profile_present=true profile_hash=0123456789abcdef"
            ),
        ),
    )
    monkeypatch.setattr(
        DiscordBotTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Discord bot auth ok: bot_id=739251864203918576 bot_profile_present=true",
        ),
    )
    monkeypatch.setattr(
        TelegramBotTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Telegram bot auth ok: bot_id=725419863 bot_profile_present=true",
        ),
    )
    monkeypatch.setattr(
        NotionTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "Notion users me ok: user_id=3c90c3cc-0d44-4b50-8888-8dd25736052a "
                "user_profile_present=true profile_hash=0123456789abcdef"
            ),
        ),
    )
    monkeypatch.setattr(
        DatadogApiKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Datadog API key valid: site=datadoghq.eu proof=valid_true",
        ),
    )
    monkeypatch.setattr(
        CloudflareApiTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Cloudflare token valid: token_id=abcdef1234567890abcdef1234567890 status=active",
        ),
    )
    monkeypatch.setattr(
        VercelTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "Vercel user ok: user_id=usr_abcdefghijklmnop "
                "user_profile_present=true profile_hash=0123456789abcdef"
            ),
        ),
    )
    monkeypatch.setattr(
        NetlifyTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "Netlify user ok: user_id=netlify-user-123 "
                "user_profile_present=true profile_hash=0123456789abcdef"
            ),
        ),
    )
    monkeypatch.setattr(
        PostHogPersonalApiKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "PostHog users me ok: host=eu.posthog.com "
                "user_id=018f9b7d-1234-4567-9abc-def012345678 "
                "user_profile_present=true profile_hash=0123456789abcdef"
            ),
        ),
    )
    monkeypatch.setattr(
        SentryAuthTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "Sentry organizations ok: org_id=4505524236910592 "
                "org_slug_present=true org_slug_stable=true org_slug_hash=d2836b7de9447c4a"
            ),
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 10
    assert summary["succeeded"] == 10
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"VALIDATED": 9, "UNVERIFIED": 1}

    results_by_service = {str(row["asset_type"]): row for row in summary["results"]}
    assert results_by_service["cloudflare"]["identifier"] == (
        "abcdef1234567890abcdef1234567890"
    )
    assert results_by_service["huggingface"]["identifier"] == "acme-mlops"
    assert results_by_service["discord"]["identifier"] == "739251864203918576"
    assert results_by_service["telegram"]["identifier"] == "725419863"
    assert results_by_service["notion"]["identifier"] == (
        "3c90c3cc-0d44-4b50-8888-8dd25736052a"
    )
    assert results_by_service["datadog"]["identifier"] == "observability.env"
    assert results_by_service["datadog"]["validation_status"] == "UNVERIFIED"
    assert results_by_service["vercel"]["identifier"] == "usr_abcdefghijklmnop"
    assert results_by_service["netlify"]["identifier"] == "netlify-user-123"
    assert results_by_service["posthog"]["identifier"] == (
        "eu.posthog.com/018f9b7d-1234-4567-9abc-def012345678"
    )
    assert results_by_service["sentry"]["identifier"] == "4505524236910592"

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY asset_type
            """
        ).fetchall()
        assert validation_rows == [
            (
                "cloudflare",
                "abcdef1234567890abcdef1234567890",
                "VALIDATED",
                "cloudflare_token_verify",
            ),
            (
                "datadog",
                "observability.env",
                "UNVERIFIED",
                "datadog_api_key_validate",
            ),
            (
                "discord",
                "739251864203918576",
                "VALIDATED",
                "discord_current_user",
            ),
            (
                "huggingface",
                "acme-mlops",
                "VALIDATED",
                "huggingface_whoami_v2",
            ),
            (
                "netlify",
                "netlify-user-123",
                "VALIDATED",
                "netlify_current_user",
            ),
            (
                "notion",
                "3c90c3cc-0d44-4b50-8888-8dd25736052a",
                "VALIDATED",
                "notion_users_me",
            ),
            (
                "posthog",
                "eu.posthog.com/018f9b7d-1234-4567-9abc-def012345678",
                "VALIDATED",
                "posthog_users_me",
            ),
            (
                "sentry",
                "4505524236910592",
                "VALIDATED",
                "sentry_list_organizations",
            ),
            (
                "telegram",
                "725419863",
                "VALIDATED",
                "telegram_get_me",
            ),
            (
                "vercel",
                "usr_abcdefghijklmnop",
                "VALIDATED",
                "vercel_user_get",
            ),
        ]

        key_rows = con.execute(
            """
            SELECT service, validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id IN (44, 45, 46, 47, 48, 49, 50, 51, 52, 53)
            ORDER BY service
            """
        ).fetchall()
        assert key_rows[0][0] == "cloudflare"
        assert key_rows[0][1] == "ACTIVE"
        assert str(key_rows[0][2] or "").startswith("VALIDATED:cloudflare_token_verify:")
        assert key_rows[1][0] == "datadog"
        assert key_rows[1][1] == "UNCONFIRMED"
        assert str(key_rows[1][2] or "").startswith("UNVERIFIED:datadog_api_key_validate:")
        assert key_rows[2][0] == "discord"
        assert key_rows[2][1] == "ACTIVE"
        assert str(key_rows[2][2] or "").startswith("VALIDATED:discord_current_user:")
        assert key_rows[3][0] == "huggingface"
        assert key_rows[3][1] == "ACTIVE"
        assert str(key_rows[3][2] or "").startswith("VALIDATED:huggingface_whoami_v2:")
        assert key_rows[4][0] == "netlify"
        assert key_rows[4][1] == "ACTIVE"
        assert str(key_rows[4][2] or "").startswith("VALIDATED:netlify_current_user:")
        assert key_rows[5][0] == "notion"
        assert key_rows[5][1] == "ACTIVE"
        assert str(key_rows[5][2] or "").startswith("VALIDATED:notion_users_me:")
        assert key_rows[6][0] == "posthog"
        assert key_rows[6][1] == "ACTIVE"
        assert str(key_rows[6][2] or "").startswith("VALIDATED:posthog_users_me:")
        assert key_rows[7][0] == "sentry"
        assert key_rows[7][1] == "ACTIVE"
        assert str(key_rows[7][2] or "").startswith("VALIDATED:sentry_list_organizations:")
        assert key_rows[8][0] == "telegram"
        assert key_rows[8][1] == "ACTIVE"
        assert str(key_rows[8][2] or "").startswith("VALIDATED:telegram_get_me:")
        assert key_rows[9][0] == "vercel"
        assert key_rows[9][1] == "ACTIVE"
        assert str(key_rows[9][2] or "").startswith("VALIDATED:vercel_user_get:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY title
            """
        ).fetchall()
        assert findings == [
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed cloudflare credential reference",
            ),
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed discord credential reference",
            ),
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed huggingface credential reference",
            ),
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed netlify credential reference",
            ),
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed notion credential reference",
            ),
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed posthog credential reference",
            ),
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed sentry credential reference",
            ),
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed telegram credential reference",
            ),
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed vercel credential reference",
            ),
        ]
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_newer_provider_active_results_without_stable_proof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES (?, 1001, '', ?, ?, 'artifact', '', ?, ?, ?, 'UNCONFIRMED')
            """,
            [
                (
                    54,
                    "cloudflare",
                    "cloudflare_api_token",
                    "edge.env",
                    "CCCC...CCCC",
                    "ciphertext-cloudflare-low-signal",
                ),
                (
                    55,
                    "vercel",
                    "vercel_access_token",
                    "deploy.env",
                    "VVVV...VVVV",
                    "ciphertext-vercel-low-signal",
                ),
                (
                    56,
                    "netlify",
                    "netlify_personal_access_token",
                    "static.env",
                    "NNNN...NNNN",
                    "ciphertext-netlify-low-signal",
                ),
                (
                    57,
                    "posthog",
                    "posthog_personal_api_key",
                    "analytics.env",
                    "phx_...PPPP",
                    "ciphertext-posthog-low-signal",
                ),
                (
                    58,
                    "sentry",
                    "sentry_auth_token",
                    "errors.env",
                    "SSSS...SSSS",
                    "ciphertext-sentry-low-signal",
                ),
                (
                    59,
                    "datadog",
                    "datadog_api_key",
                    "observability.env",
                    "0123...cdef",
                    "ciphertext-datadog-low-signal",
                ),
                (
                    61,
                    "huggingface",
                    "huggingface_token",
                    "models.env",
                    "hf_...HHHH",
                    "ciphertext-huggingface-low-signal",
                ),
                (
                    60,
                    "notion",
                    "notion_integration_token",
                    "workspace.env",
                    "ntn_...NNNN",
                    "ciphertext-notion-low-signal",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    def _fake_decrypt(value: str) -> str:
        if value == "ciphertext-cloudflare-low-signal":
            return "C" * 40
        if value == "ciphertext-vercel-low-signal":
            return "V" * 40
        if value == "ciphertext-netlify-low-signal":
            return "N" * 40
        if value == "ciphertext-posthog-low-signal":
            return "phx_" + "P" * 40
        if value == "ciphertext-sentry-low-signal":
            return "S" * 40
        if value == "ciphertext-datadog-low-signal":
            return "0123456789abcdef0123456789abcdef"
        if value == "ciphertext-huggingface-low-signal":
            return "hf_" + "H" * 36
        if value == "ciphertext-notion-low-signal":
            return "ntn_" + "N" * 40
        return value

    monkeypatch.setattr(cloud_validate, "_decrypt_secret", _fake_decrypt)
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        CloudflareApiTokenValidator,
        DatadogApiKeyValidator,
        HuggingFaceTokenValidator,
        NetlifyTokenValidator,
        NotionTokenValidator,
        PostHogPersonalApiKeyValidator,
        SentryAuthTokenValidator,
        ValidationResult,
        ValidationState,
        VercelTokenValidator,
    )

    monkeypatch.setattr(
        CloudflareApiTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Cloudflare token valid: token_id=abcdef1234567890abcdef1234567890 status=pending",
        ),
    )
    monkeypatch.setattr(
        VercelTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Vercel user ok: user_id=usr_abcdefghijklmnop",
        ),
    )
    monkeypatch.setattr(
        NetlifyTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Netlify user ok: user_id=netlify-user-123",
        ),
    )
    monkeypatch.setattr(
        PostHogPersonalApiKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "PostHog users me ok: host=eu.posthog.com "
                "user_id=018f9b7d-1234-4567-9abc-def012345678"
            ),
        ),
    )
    monkeypatch.setattr(
        SentryAuthTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "Sentry organizations ok: org_id=4505524236910592 "
                f"org_slug_present=true org_slug_stable=true org_slug_hash={'0' * 64}"
            ),
        ),
    )
    monkeypatch.setattr(
        DatadogApiKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Datadog API key valid: site=datadoghq.eu",
        ),
    )
    monkeypatch.setattr(
        HuggingFaceTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Hugging Face auth ok: user=model-owner user_profile_present=true",
        ),
    )
    monkeypatch.setattr(
        NotionTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "Notion users me ok: user_id=3c90c3cc-0d44-4b50-8888-8dd25736052a"
            ),
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=3,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 8
    assert summary["succeeded"] == 8
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 8}

    results_by_service = {str(row["asset_type"]): row for row in summary["results"]}
    assert results_by_service["cloudflare"]["validation_method"] == "cloudflare_token_verify"
    assert results_by_service["datadog"]["validation_method"] == "datadog_api_key_validate"
    assert results_by_service["huggingface"]["validation_method"] == "huggingface_whoami_v2"
    assert results_by_service["notion"]["validation_method"] == "notion_users_me"
    assert results_by_service["vercel"]["validation_method"] == "vercel_user_get"
    assert results_by_service["netlify"]["validation_method"] == "netlify_current_user"
    assert results_by_service["posthog"]["validation_method"] == "posthog_users_me"
    assert results_by_service["sentry"]["validation_method"] == "sentry_list_organizations"
    assert {
        str(row["validation_status"])
        for row in results_by_service.values()
    } == {"UNVERIFIED"}

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY asset_type
            """
        ).fetchall()
        assert validation_rows == [
            ("cloudflare", "UNVERIFIED", "cloudflare_token_verify"),
            ("datadog", "UNVERIFIED", "datadog_api_key_validate"),
            ("huggingface", "UNVERIFIED", "huggingface_whoami_v2"),
            ("netlify", "UNVERIFIED", "netlify_current_user"),
            ("notion", "UNVERIFIED", "notion_users_me"),
            ("posthog", "UNVERIFIED", "posthog_users_me"),
            ("sentry", "UNVERIFIED", "sentry_list_organizations"),
            ("vercel", "UNVERIFIED", "vercel_user_get"),
        ]

        key_rows = con.execute(
            """
            SELECT service, validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id IN (54, 55, 56, 57, 58, 59, 60, 61)
            ORDER BY service
            """
        ).fetchall()
        assert [(row[0], row[1]) for row in key_rows] == [
            ("cloudflare", "UNCONFIRMED"),
            ("datadog", "UNCONFIRMED"),
            ("huggingface", "UNCONFIRMED"),
            ("netlify", "UNCONFIRMED"),
            ("notion", "UNCONFIRMED"),
            ("posthog", "UNCONFIRMED"),
            ("sentry", "UNCONFIRMED"),
            ("vercel", "UNCONFIRMED"),
        ]
        assert all(str(row[2] or "").startswith("UNVERIFIED:") for row in key_rows)

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY title
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_posthog_arbitrary_host_proof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (62, 1001, '', 'posthog', 'posthog_personal_api_key', 'artifact',
                 '', 'posthog.env', 'phx_...PPPP', 'ciphertext-posthog-arbitrary-host', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "phx_" + "P" * 40,
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        PostHogPersonalApiKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        PostHogPersonalApiKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "PostHog users me ok: host=example.com "
                "user_id=018f9b7d-1234-4567-9abc-def012345678 "
                "user_profile_present=true"
            ),
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 1}
    assert summary["results"][0]["key_id"] == 62
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["identifier"] == "posthog.env"
    assert summary["results"][0]["validation_method"] == "posthog_users_me"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "posthog",
            "posthog.env",
            "UNVERIFIED",
            "posthog_users_me",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=62
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith("UNVERIFIED:posthog_users_me:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_processes_validatable_gitlab_pat_rows_without_cloud_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (41, 1001, '', 'gitlab', 'gitlab_pat', 'artifact',
                 '', 'gitlab.env', 'glpa...YYYY', 'ciphertext-gitlab', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "glpat-" + "Y" * 20,
    )
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        GitlabPatValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        GitlabPatValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=(
                "GitLab user ok: user_id=739251 username=delta-ops user_profile_present=true "
                "profile_url_matches_login=true"
            ),
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["key_id"] == 41
    assert summary["results"][0]["validation_status"] == "VALIDATED"
    assert summary["results"][0]["validation_method"] == "gitlab_current_user_api"
    assert summary["results"][0]["identifier"] == "delta-ops"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "gitlab",
            "delta-ops",
            "VALIDATED",
            "gitlab_current_user_api",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=41
            """
        ).fetchone()
        assert key_row[0] == "ACTIVE"
        assert str(key_row[1] or "").startswith(
            "VALIDATED:gitlab_current_user_api:"
        )

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == [
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed gitlab credential reference",
            )
        ]
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_mailchimp_ping_only_proof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (18, 1001, '', 'mailchimp', 'mailchimp_api_key', 'artifact',
                 '', 'newsletter.env', '1234...-us1', 'ciphertext-mailchimp', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "1234567890abcdef1234567890abcdef-us1",
    )
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        MailchimpKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        MailchimpKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Mailchimp ping ok: dc=us1 health=Everything's Chimpy!",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 1}
    assert summary["results"][0]["key_id"] == 18
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["validation_method"] == "mailchimp_ping_api"
    assert summary["results"][0]["identifier"] == "us1"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("mailchimp", "us1", "UNVERIFIED", "mailchimp_ping_api")

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=18
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith("UNVERIFIED:mailchimp_ping_api:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_mailchimp_chimpy_substring_proof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (18, 1001, '', 'mailchimp', 'mailchimp_api_key', 'artifact',
                 '', 'newsletter.env', '1234...-us1', 'ciphertext-mailchimp', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "1234567890abcdef1234567890abcdef-us1",
    )
    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        MailchimpKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        MailchimpKeyValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Mailchimp ping ok: dc=us1 health=not chimpy",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 1}
    assert summary["results"][0]["key_id"] == 18
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["validation_method"] == "mailchimp_ping_api"
    assert summary["results"][0]["identifier"] == "us1"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("mailchimp", "us1", "UNVERIFIED", "mailchimp_ping_api")

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=18
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith("UNVERIFIED:mailchimp_ping_api:")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_sweep_pending_cloud_validations_processes_validatable_slack_token_rows_without_cloud_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (13, 1001, '', 'slack', 'slack_bot_token', 'artifact',
                 '', 'chatops.env', 'xoxb...UvWx', 'ciphertext-slack', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx",
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        SlackTokenValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        SlackTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Slack auth ok: actor_id=U7A3C9K2 team_id=T9B2D6F4",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["key_id"] == 13
    assert summary["results"][0]["validation_status"] == "VALIDATED"
    assert summary["results"][0]["validation_method"] == "slack_auth_test"
    assert summary["results"][0]["identifier"] == "t9b2d6f4/u7a3c9k2"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "slack",
            "t9b2d6f4/u7a3c9k2",
            "VALIDATED",
            "slack_auth_test",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=13
            """
        ).fetchone()
        assert key_row[0] == "ACTIVE"
        assert str(key_row[1] or "").startswith("VALIDATED:slack_auth_test:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == [
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed slack credential reference",
            )
        ]
    finally:
        con.close()


@pytest.mark.parametrize(
    "validation_detail",
    [
        "Slack auth ok: actor_id=UAAAA team_id=TAAAA",
        "Slack auth ok: actor_id=U1234567 team_id=T7654321",
    ],
)
def test_sweep_pending_cloud_validations_downgrades_slack_low_signal_proof(
    tmp_path: Path,
    monkeypatch,
    validation_detail: str,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (13, 1001, '', 'slack', 'slack_bot_token', 'artifact',
                 '', 'chatops.env', 'xoxb...UvWx', 'ciphertext-slack', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx",
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        SlackTokenValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        SlackTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail=validation_detail,
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 1}
    assert summary["results"][0]["key_id"] == 13
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["validation_method"] == "slack_auth_test"
    assert summary["results"][0]["identifier"] == "chatops.env"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("slack", "chatops.env", "UNVERIFIED", "slack_auth_test")

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=13
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith("UNVERIFIED:slack_auth_test:")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_slack_single_identifier_proof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (13, 1001, '', 'slack', 'slack_bot_token', 'artifact',
                 '', 'chatops.env', 'xoxb...UvWx', 'ciphertext-slack', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx",
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        SlackTokenValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        SlackTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Slack auth ok: actor_id=U1234567",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 1}
    assert summary["results"][0]["key_id"] == 13
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["validation_method"] == "slack_auth_test"
    assert summary["results"][0]["identifier"] == "chatops.env"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("slack", "chatops.env", "UNVERIFIED", "slack_auth_test")

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=13
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith("UNVERIFIED:slack_auth_test:")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_sweep_pending_cloud_validations_keeps_active_key_without_provider_proof_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (51, 1001, '', 'slack', 'slack_bot_token', 'artifact',
                 '', 'chatops.env', 'xoxb...UvWx', 'ciphertext-slack-low-signal', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx",
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        SlackTokenValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        SlackTokenValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Slack auth ok: token accepted",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["UNVERIFIED"] == 1
    assert summary["results"][0]["key_id"] == 51
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["validation_method"] == "slack_auth_test"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("slack", "UNVERIFIED", "slack_auth_test")

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=51
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith("UNVERIFIED:slack_auth_test:")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_processes_colocated_twilio_pair_without_cloud_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (9, 1001, '', 'twilio', 'twilio_account_sid', 'artifact',
                 '', 'mobile-config.js', 'AC12...cdef', 'ciphertext-sid', 'UNCONFIRMED')
            """
        )
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (10, 1001, '', 'twilio', 'twilio_auth_token', 'artifact',
                 '', 'mobile-config.js', 'abcd...7890', 'ciphertext-token', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    def _fake_decrypt(value: str) -> str:
        if value == "ciphertext-sid":
            return "AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3"
        if value == "ciphertext-token":
            return "abcdef1234567890abcdef1234567890"
        return value

    monkeypatch.setattr(cloud_validate, "_decrypt_secret", _fake_decrypt)

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        TwilioKeyValidator,
        ValidationResult,
        ValidationState,
    )

    def _fake_twilio_validate(self, key, auth_token=None, proxy=None, **kwargs):  # noqa: ANN001, ARG001
        if key == "AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3" and auth_token == "abcdef1234567890abcdef1234567890":
            return ValidationResult(
                state=ValidationState.ACTIVE,
                detail=(
                    "Twilio account accessible: sid=AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3 "
                    "status=active type=Full"
                ),
            )
        return ValidationResult(
            state=ValidationState.UNCONFIRMED,
            detail="Twilio auth token not co-located",
        )

    monkeypatch.setattr(TwilioKeyValidator, "validate", _fake_twilio_validate)

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["key_id"] == 9
    assert summary["results"][0]["validation_status"] == "VALIDATED"
    assert summary["results"][0]["validation_method"] == "twilio_account_api"
    assert summary["results"][0]["identifier"] == "AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "twilio",
            "AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3",
            "VALIDATED",
            "twilio_account_api",
        )

        sid_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=9
            """
        ).fetchone()
        assert sid_row[0] == "ACTIVE"
        assert str(sid_row[1] or "").startswith("VALIDATED:twilio_account_api:")

        token_row = con.execute(
            """
            SELECT validation_state
            FROM key_scanner_findings
            WHERE id=10
            """
        ).fetchone()
        assert token_row == ("UNCONFIRMED",)

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == [
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed twilio credential reference",
            )
        ]
    finally:
        con.close()


def test_sweep_pending_cloud_validations_keeps_twilio_rate_limit_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (29, 1001, '', 'twilio', 'twilio_account_sid', 'artifact',
                 '', 'mobile-config.js', 'AC12...cdef', 'ciphertext-sid-rate-limited', 'UNCONFIRMED')
            """
        )
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (30, 1001, '', 'twilio', 'twilio_auth_token', 'artifact',
                 '', 'mobile-config.js', 'abcd...7890', 'ciphertext-token-rate-limited', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    def _fake_decrypt(value: str) -> str:
        if value == "ciphertext-sid-rate-limited":
            return "AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3"
        if value == "ciphertext-token-rate-limited":
            return "abcdef1234567890abcdef1234567890"
        return value

    monkeypatch.setattr(cloud_validate, "_decrypt_secret", _fake_decrypt)

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        TwilioKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        TwilioKeyValidator,
        "validate",
        lambda self, key, auth_token=None, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.UNCONFIRMED,
            detail="HTTP 429",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["UNVERIFIED"] == 1
    assert summary["results"][0]["key_id"] == 29
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["validation_method"] == "twilio_account_api"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "twilio",
            "AC6f8a2c9d4e1b73f5a0c8d2e9f4a6b1c3",
            "UNVERIFIED",
            "twilio_account_api",
        )

        sid_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=29
            """
        ).fetchone()
        assert sid_row[0] == "UNCONFIRMED"
        assert str(sid_row[1] or "").startswith("UNVERIFIED:twilio_account_api:HTTP 429")

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_skips_context_only_twilio_token_rows(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (19, 1001, '', 'twilio', 'twilio_auth_token', 'artifact',
                 '', 'mobile-config.js', 'abcd...7890', 'ciphertext-token', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: "abcdef1234567890abcdef1234567890",
    )

    from forge.utils.intel.secret_finder import TwilioKeyValidator  # noqa: PLC0415

    monkeypatch.setattr(
        TwilioKeyValidator,
        "validate",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("context-only token row should not validate")),  # noqa: ARG005
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 0
    assert summary["results"] == []

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT COUNT(*)
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_rows == (0,)
    finally:
        con.close()


def test_sweep_pending_cloud_validations_processes_colocated_aws_pair_without_cloud_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (11, 1001, '', 'aws', 'aws_access_key_id', 'artifact',
                 '', 'secrets.env', 'AKIA...MPLE', 'ciphertext-aws-access', 'UNCONFIRMED')
            """
        )
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (12, 1001, '', 'aws', 'aws_secret_access_key', 'artifact',
                 '', 'secrets.env', 'wJal...EKEY', 'ciphertext-aws-secret', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    def _fake_decrypt(value: str) -> str:
        if value == "ciphertext-aws-access":
            return "AKIAIOSFODNN7EXAMPLE"
        if value == "ciphertext-aws-secret":
            return "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        return value

    monkeypatch.setattr(cloud_validate, "_decrypt_secret", _fake_decrypt)

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AwsKeyValidator,
        ValidationResult,
        ValidationState,
    )

    def _fake_aws_validate(self, key, secret=None, proxy=None, **kwargs):  # noqa: ANN001, ARG001
        if key == "AKIAIOSFODNN7EXAMPLE" and secret == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY":
            return ValidationResult(
                state=ValidationState.ACTIVE,
                detail="AWS AccountId: 742931608514",
            )
        return ValidationResult(
            state=ValidationState.UNCONFIRMED,
            detail="AWS secret key not co-located",
        )

    monkeypatch.setattr(AwsKeyValidator, "validate", _fake_aws_validate)

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["key_id"] == 11
    assert summary["results"][0]["validation_status"] == "VALIDATED"
    assert summary["results"][0]["validation_method"] == "aws_sts_get_caller_identity"
    assert summary["results"][0]["identifier"] == "742931608514"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "aws",
            "742931608514",
            "VALIDATED",
            "aws_sts_get_caller_identity",
        )

        access_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=11
            """
        ).fetchone()
        assert access_row[0] == "ACTIVE"
        assert str(access_row[1] or "").startswith("VALIDATED:aws_sts_get_caller_identity:")

        secret_row = con.execute(
            """
            SELECT validation_state
            FROM key_scanner_findings
            WHERE id=12
            """
        ).fetchone()
        assert secret_row == ("UNCONFIRMED",)

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == [
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed aws credential reference",
            )
        ]
    finally:
        con.close()


def test_sweep_pending_cloud_validations_keeps_aws_rate_limit_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (?, 1001, '', 'aws', ?, 'artifact', '', 'secrets.env', ?, ?, 'UNCONFIRMED')
            """,
            [
                (
                    31,
                    "aws_access_key_id",
                    "AKIA...MPLE",
                    "ciphertext-aws-rate-limited-access",
                ),
                (
                    32,
                    "aws_secret_access_key",
                    "wJal...EKEY",
                    "ciphertext-aws-rate-limited-secret",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    def _fake_decrypt(value: str) -> str:
        if value == "ciphertext-aws-rate-limited-access":
            return "AKIAIOSFODNN7EXAMPLE"
        if value == "ciphertext-aws-rate-limited-secret":
            return "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        return value

    monkeypatch.setattr(cloud_validate, "_decrypt_secret", _fake_decrypt)

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AwsKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        AwsKeyValidator,
        "validate",
        lambda self, key, secret=None, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.UNCONFIRMED,
            detail="HTTP 429",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["UNVERIFIED"] == 1
    assert summary["results"][0]["key_id"] == 31
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["validation_method"] == "aws_sts_get_caller_identity"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "aws",
            "secrets.env",
            "UNVERIFIED",
            "aws_sts_get_caller_identity",
        )

        key_rows = con.execute(
            """
            SELECT id, validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id IN (31, 32)
            ORDER BY id
            """
        ).fetchall()
        assert key_rows[0][1] == "UNCONFIRMED"
        assert str(key_rows[0][2] or "").startswith(
            "UNVERIFIED:aws_sts_get_caller_identity:HTTP 429"
        )
        assert key_rows[1] == (32, "UNCONFIRMED", None)

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_aws_active_result_without_stable_account_id(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (?, 1001, '', 'aws', ?, 'artifact', '', 'secrets.env', ?, ?, 'UNCONFIRMED')
            """,
            [
                (
                    21,
                    "aws_access_key_id",
                    "AKIA...MPLE",
                    "ciphertext-aws-low-signal-access",
                ),
                (
                    22,
                    "aws_secret_access_key",
                    "wJal...EKEY",
                    "ciphertext-aws-low-signal-secret",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    def _fake_decrypt(value: str) -> str:
        if value == "ciphertext-aws-low-signal-access":
            return "AKIAIOSFODNN7EXAMPLE"
        if value == "ciphertext-aws-low-signal-secret":
            return "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        return value

    monkeypatch.setattr(cloud_validate, "_decrypt_secret", _fake_decrypt)

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AwsKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        AwsKeyValidator,
        "validate",
        lambda self, key, secret=None, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="AWS AccountId: 000000000000",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 1}
    assert summary["results"][0]["key_id"] == 21
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["validation_method"] == "aws_sts_get_caller_identity"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("aws", "UNVERIFIED", "aws_sts_get_caller_identity")

        key_rows = con.execute(
            """
            SELECT id, validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id IN (21, 22)
            ORDER BY id
            """
        ).fetchall()
        assert key_rows[0][1] == "UNCONFIRMED"
        assert str(key_rows[0][2] or "").startswith("UNVERIFIED:")
        assert key_rows[1] == (22, "UNCONFIRMED", None)

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_processes_validatable_azure_connection_string_without_cloud_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (14, 1001, '', 'azure', 'azure_storage_key', 'artifact',
                 '', 'storage.env', 'Default...e==', 'ciphertext-azure', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: (
            "DefaultEndpointsProtocol=https;"
            "AccountName=acmestorage;"
            f"AccountKey={'A' * 86}=="
        ),
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AzureStorageConnectionStringValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        AzureStorageConnectionStringValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Azure blob list accessible: account=acmestorage containers=1",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["key_id"] == 14
    assert summary["results"][0]["validation_status"] == "VALIDATED"
    assert summary["results"][0]["validation_method"] == "azure_blob_list_containers_shared_key"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "azure",
            "acmestorage",
            "VALIDATED",
            "azure_blob_list_containers_shared_key",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=14
            """
        ).fetchone()
        assert key_row[0] == "ACTIVE"
        assert str(key_row[1] or "").startswith(
            "VALIDATED:azure_blob_list_containers_shared_key:"
        )

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type, title
            """
        ).fetchall()
        assert findings == [
            (
                "DETERMINISTIC_KEY_EXPOSURE",
                "HIGH",
                "Validated exposed azure credential reference",
            )
        ]
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_azure_mismatched_account_proof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (15, 1001, '', 'azure', 'azure_storage_key', 'artifact',
                 '', 'storage.env', 'Default...e==', 'ciphertext-azure-mismatch', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: (
            "DefaultEndpointsProtocol=https;"
            "AccountName=acmestorage;"
            f"AccountKey={'A' * 86}=="
        ),
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AzureStorageConnectionStringValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        AzureStorageConnectionStringValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Azure blob list accessible: account=otherstorage containers=2",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 1}
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["identifier"] == "acmestorage"
    assert summary["results"][0]["validation_method"] == "azure_blob_list_containers_shared_key"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "azure",
            "acmestorage",
            "UNVERIFIED",
            "azure_blob_list_containers_shared_key",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=15
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith(
            "UNVERIFIED:azure_blob_list_containers_shared_key:"
        )

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_azure_empty_container_listings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (15, 1001, '', 'azure', 'azure_storage_key', 'artifact',
                 '', 'empty-storage.env', 'Default...e==', 'ciphertext-azure-empty', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: (
            "DefaultEndpointsProtocol=https;"
            "AccountName=emptystorage;"
            f"AccountKey={'A' * 86}=="
        ),
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AzureStorageConnectionStringValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        AzureStorageConnectionStringValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Azure blob list accessible: account=emptystorage containers=0",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 1}
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["identifier"] == "emptystorage"
    assert summary["results"][0]["validation_method"] == "azure_blob_list_containers_shared_key"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "azure",
            "emptystorage",
            "UNVERIFIED",
            "azure_blob_list_containers_shared_key",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=15
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith(
            "UNVERIFIED:azure_blob_list_containers_shared_key:"
        )

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_downgrades_azure_placeholder_account_proof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (16, 1001, '', 'azure', 'azure_storage_key', 'artifact',
                 '', 'placeholder-storage.env', 'Default...e==', 'ciphertext-azure-placeholder', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: (
            "DefaultEndpointsProtocol=https;"
            "AccountName=aaaaaaaaaaaa;"
            f"AccountKey={'A' * 86}=="
        ),
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AzureStorageConnectionStringValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        AzureStorageConnectionStringValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Azure blob list accessible: account=aaaaaaaaaaaa containers=2",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 1}
    assert summary["results"][0]["validation_status"] == "UNVERIFIED"
    assert summary["results"][0]["identifier"] == "placeholder-storage.env"
    assert summary["results"][0]["validation_method"] == "azure_blob_list_containers_shared_key"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "azure",
            "placeholder-storage.env",
            "UNVERIFIED",
            "azure_blob_list_containers_shared_key",
        )

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=16
            """
        ).fetchone()
        assert key_row[0] == "UNCONFIRMED"
        assert str(key_row[1] or "").startswith(
            "UNVERIFIED:azure_blob_list_containers_shared_key:"
        )

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_validations_only_unattempted_skips_previously_attempted_rows(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state, validation_detail, validated_at)
            VALUES
                (21, 1001, '', 'stripe', 'stripe_live_secret_key', 'artifact',
                 '', 'already-tried-stripe.env', 'sk_live_...1234', 'ciphertext-stripe', 'UNCONFIRMED',
                 'UNVERIFIED:stripe_balance_api:previous attempt', CURRENT_TIMESTAMP),
                (22, 1001, '', 'slack', 'slack_bot_token', 'artifact',
                 '', 'already-tried-slack.env', 'xoxb...UvWx', 'ciphertext-slack', 'UNCONFIRMED',
                 'UNVERIFIED:slack_auth_test:previous attempt', CURRENT_TIMESTAMP),
                (23, 1001, '', 'azure', 'azure_storage_key', 'artifact',
                 '', 'fresh-azure.env', 'Default...e==', 'ciphertext-azure', 'UNCONFIRMED',
                 NULL, NULL)
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: (
            "DefaultEndpointsProtocol=https;"
            "AccountName=onlynewstorage;"
            f"AccountKey={'A' * 86}=="
        ),
    )

    from forge.utils.intel.secret_finder import (  # noqa: PLC0415
        AzureStorageConnectionStringValidator,
        SlackTokenValidator,
        StripeKeyValidator,
        ValidationResult,
        ValidationState,
    )

    monkeypatch.setattr(
        StripeKeyValidator,
        "validate",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("previous stripe row should not retry")),  # noqa: ARG005
    )
    monkeypatch.setattr(
        SlackTokenValidator,
        "validate",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("previous slack row should not retry")),  # noqa: ARG005
    )
    monkeypatch.setattr(
        AzureStorageConnectionStringValidator,
        "validate",
        lambda self, key, proxy=None, **kwargs: ValidationResult(  # noqa: ARG005
            state=ValidationState.ACTIVE,
            detail="Azure blob list accessible: account=onlynewstorage containers=1",
        ),
    )

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=2,
        max_workers=2,
        only_unattempted=True,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["results"][0]["key_id"] == 23
    assert summary["results"][0]["identifier"] == "onlynewstorage"

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY id ASC
            """
        ).fetchall()
        assert validation_rows == [("azure", "onlynewstorage", "VALIDATED")]

        old_rows = con.execute(
            """
            SELECT id, validation_detail
            FROM key_scanner_findings
            WHERE id IN (21, 22)
            ORDER BY id ASC
            """
        ).fetchall()
        assert old_rows == [
            (21, "UNVERIFIED:stripe_balance_api:previous attempt"),
            (22, "UNVERIFIED:slack_auth_test:previous attempt"),
        ]
    finally:
        con.close()


def test_run_cloud_validate_derives_supabase_identifier_from_key_only_secret(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (3, 1001, '', 'supabase', 'supabase_mobile_config', 'artifact',
                 '', 'bundle.js', 'sb_publishable', 'ciphertext-placeholder', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda _value: (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFjbWUtd29ya3NwYWNlIiwicm9sZSI6ImFub24ifQ."
            "signature999"
        ),
    )
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseRestAccessClient)

    result = cloud_validate.run_cloud_validate(3, "test_bucket", 10, db_path)

    assert result["status"] == "success"
    assert result["identifier"] == "acme-workspace"
    assert result["validation_status"] == "VALIDATED"
    assert result["validation_method"] == "supabase_rest_root"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("supabase", "acme-workspace", "VALIDATED", "supabase_rest_root")

        key_row = con.execute(
            """
            SELECT validation_state, validation_detail
            FROM key_scanner_findings
            WHERE id=3
            """
        ).fetchone()
        assert key_row[0] == "ACTIVE"
        assert "VALIDATED:supabase_rest_root" in str(key_row[1])
    finally:
        con.close()


def test_run_cloud_asset_validate_persists_direct_asset_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _FirebaseLiveDataClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "firebase",
        "acme-firebase-prod",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "VALIDATED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("firebase", "acme-firebase-prod", "VALIDATED")

        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row == ("HIGH", "Validated Firebase data exposure")
    finally:
        con.close()


def test_run_cloud_asset_validate_preserves_case_sensitive_provider_identifier(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    _AwsClientReferenceClient.calls.clear()
    _AwsClientReferenceClient.kwargs_seen.clear()
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AwsClientReferenceClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_cognito_user_pool",
        "us-east-1_AbCd12345",
        db_path,
    )

    assert result["status"] == "success"
    assert result["identifier"] == "us-east-1_abcd12345"
    assert result["provider_identifier"] == "us-east-1_AbCd12345"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert result["validation_method"] == "aws_cognito_user_pool_oidc_discovery"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT identifier, provider_identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "us-east-1_abcd12345",
            "us-east-1_AbCd12345",
            "ACCESSIBLE_BUT_NO_DATA",
            "aws_cognito_user_pool_oidc_discovery",
        )
        cloud_row = con.execute(
            """
            SELECT identifier, provider_identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert cloud_row == ("us-east-1_abcd12345", "us-east-1_AbCd12345")

        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row is None
    finally:
        con.close()
    assert _AwsClientReferenceClient.calls == [
        "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCd12345/.well-known/openid-configuration"
    ]
    assert _AwsClientReferenceClient.kwargs_seen == [{}]


def test_run_cloud_asset_validate_batch_processes_aws_client_references_without_findings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    _AwsClientReferenceClient.calls.clear()
    _AwsClientReferenceClient.kwargs_seen.clear()
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AwsClientReferenceClient)

    summary = cloud_validate.run_cloud_asset_validate_batch(
        1001,
        [
            ("aws_cognito_app_client", "us-east-1_AbCd12345/abcclient123"),
            ("aws_cognito_identity_pool", "us-east-1:11111111-2222-3333-4444-555555555555"),
            ("aws_appsync_api", "us-east-1/abc123456789"),
            ("aws_pinpoint_app", "us-east-1/pinpoint123"),
        ],
        db_path,
        max_workers=1,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 4
    assert summary["succeeded"] == 4
    assert summary["failed"] == 0
    assert summary["status_counts"] == {
        "ACCESSIBLE_BUT_NO_DATA": 2,
        "UNSUPPORTED": 2,
    }
    assert [
        (item["asset_type"], item["identifier"], item["provider_identifier"], item["validation_status"])
        for item in summary["results"]
    ] == [
        (
            "aws_cognito_app_client",
            "us-east-1_abcd12345/abcclient123",
            "us-east-1_AbCd12345/abcclient123",
            "ACCESSIBLE_BUT_NO_DATA",
        ),
        (
            "aws_cognito_identity_pool",
            "us-east-1:11111111-2222-3333-4444-555555555555",
            "us-east-1:11111111-2222-3333-4444-555555555555",
            "UNSUPPORTED",
        ),
        (
            "aws_appsync_api",
            "us-east-1/abc123456789",
            "us-east-1/abc123456789",
            "ACCESSIBLE_BUT_NO_DATA",
        ),
        (
            "aws_pinpoint_app",
            "us-east-1/pinpoint123",
            "us-east-1/pinpoint123",
            "UNSUPPORTED",
        ),
    ]

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, identifier, provider_identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert validation_rows == [
            (
                "aws_appsync_api",
                "us-east-1/abc123456789",
                "us-east-1/abc123456789",
                "ACCESSIBLE_BUT_NO_DATA",
                "aws_appsync_graphql_endpoint_reachability",
            ),
            (
                "aws_cognito_app_client",
                "us-east-1_abcd12345/abcclient123",
                "us-east-1_AbCd12345/abcclient123",
                "ACCESSIBLE_BUT_NO_DATA",
                "aws_cognito_app_client_user_pool_discovery",
            ),
            (
                "aws_cognito_identity_pool",
                "us-east-1:11111111-2222-3333-4444-555555555555",
                "us-east-1:11111111-2222-3333-4444-555555555555",
                "UNSUPPORTED",
                "registry_lookup",
            ),
            (
                "aws_pinpoint_app",
                "us-east-1/pinpoint123",
                "us-east-1/pinpoint123",
                "UNSUPPORTED",
                "registry_lookup",
            ),
        ]
        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row is None
    finally:
        con.close()
    assert _AwsClientReferenceClient.calls == [
        "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCd12345/.well-known/openid-configuration",
        "https://abc123456789.appsync-api.us-east-1.amazonaws.com/graphql",
    ]
    assert _AwsClientReferenceClient.kwargs_seen == [{}, {}]


def test_run_cloud_asset_validate_keeps_firebase_bootstrap_metadata_audit_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _FirebaseClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "firebase",
        "acme-firebase-prod",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert result["validation_method"] == "firebase_init_json"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == (
            "firebase",
            "acme-firebase-prod",
            "ACCESSIBLE_BUT_NO_DATA",
            "firebase_init_json",
        )

        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row is None
    finally:
        con.close()


def test_run_cloud_asset_validate_batch_records_managed_alias_reachability_without_findings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    class _ManagedHostingClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_ManagedHostingClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
            del kwargs
            if url in {
                "https://acme-preview.vercel.app",
                "https://acmeportal.appspot.com",
                "https://acme-edge.netlify.app",
                "https://main.d3m0amplify.amplifyapp.com",
                "https://us-central1-acmehub.cloudfunctions.net/ping",
                "https://api-prod-abc.a.run.app",
                "https://acme.github.io",
                "https://security.gitlab.io",
                "https://acme-pages.pages.dev",
                "https://worker.acme.workers.dev",
                "https://pub-acme.r2.dev",
                "https://accountid.r2.cloudflarestorage.com",
                "https://render-api.onrender.com",
                "https://acme-fly.fly.dev",
                "https://acme-railway.up.railway.app",
                "https://calm-coast-012345.2.azurestaticapps.net",
                "https://acme-heroku.herokuapp.com",
            }:
                return _FakeResponse(200, "", {"content-type": "text/html"})
            return _FakeResponse(404, "missing", {"content-type": "text/plain"})

        def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
            return self.head(url, **kwargs)

    monkeypatch.setattr(cloud_validate.httpx, "Client", _ManagedHostingClient)

    result = cloud_validate.run_cloud_asset_validate_batch(
        1001,
        [
            ("vercel", "acme-preview"),
            ("gcp_appspot", "acmeportal"),
            ("netlify", "acme-edge"),
            ("amplify", "main.d3m0amplify.amplifyapp.com"),
            ("gcp_cloudfunctions", "https://us-central1-acmehub.cloudfunctions.net/ping"),
            ("gcp_cloudfunctions", "acmehub"),
            ("gcp_cloud_run", "api-prod-abc.a.run.app"),
            ("github_pages", "acme.github.io"),
            ("gitlab_pages", "security.gitlab.io"),
            ("cloudflare_pages", "acme-pages"),
            ("cloudflare_worker", "worker.acme.workers.dev"),
            ("cloudflare_r2", "pub-acme.r2.dev"),
            ("cloudflare_r2", "accountid.r2.cloudflarestorage.com"),
            ("cloudflare_r2", "acme-r2-assets"),
            ("render", "render-api"),
            ("fly", "acme-fly"),
            ("railway", "acme-railway"),
            ("heroku", "acme-heroku"),
            ("azure_static_web_app", "calm-coast-012345.2.azurestaticapps.net"),
        ],
        db_path,
        max_workers=3,
    )

    assert result["status"] == "success"
    assert result["attempted"] == 19
    assert result["failed"] == 0
    assert result["status_counts"]["ACCESSIBLE_BUT_NO_DATA"] == 17
    assert result["status_counts"]["UNSUPPORTED"] == 2
    assert {item["asset_type"] for item in result["results"]} == {
        "amplify",
        "azure_static_web_app",
        "cloudflare_pages",
        "cloudflare_r2",
        "cloudflare_worker",
        "fly",
        "gcp_cloudfunctions",
        "gcp_cloud_run",
        "gcp_appspot",
        "github_pages",
        "gitlab_pages",
        "heroku",
        "netlify",
        "railway",
        "render",
        "vercel",
    }

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert validation_rows == [
            ("amplify", "main.d3m0amplify.amplifyapp.com", "ACCESSIBLE_BUT_NO_DATA"),
            ("azure_static_web_app", "calm-coast-012345.2.azurestaticapps.net", "ACCESSIBLE_BUT_NO_DATA"),
            ("cloudflare_pages", "acme-pages", "ACCESSIBLE_BUT_NO_DATA"),
            ("cloudflare_r2", "accountid.r2.cloudflarestorage.com", "ACCESSIBLE_BUT_NO_DATA"),
            ("cloudflare_r2", "acme-r2-assets", "UNSUPPORTED"),
            ("cloudflare_r2", "pub-acme.r2.dev", "ACCESSIBLE_BUT_NO_DATA"),
            ("cloudflare_worker", "worker.acme.workers.dev", "ACCESSIBLE_BUT_NO_DATA"),
            ("fly", "acme-fly", "ACCESSIBLE_BUT_NO_DATA"),
            ("gcp_appspot", "acmeportal", "ACCESSIBLE_BUT_NO_DATA"),
            ("gcp_cloud_run", "api-prod-abc.a.run.app", "ACCESSIBLE_BUT_NO_DATA"),
            ("gcp_cloudfunctions", "acmehub", "UNSUPPORTED"),
            (
                "gcp_cloudfunctions",
                "https://us-central1-acmehub.cloudfunctions.net/ping",
                "ACCESSIBLE_BUT_NO_DATA",
            ),
            ("github_pages", "acme.github.io", "ACCESSIBLE_BUT_NO_DATA"),
            ("gitlab_pages", "security.gitlab.io", "ACCESSIBLE_BUT_NO_DATA"),
            ("heroku", "acme-heroku", "ACCESSIBLE_BUT_NO_DATA"),
            ("netlify", "acme-edge", "ACCESSIBLE_BUT_NO_DATA"),
            ("railway", "acme-railway", "ACCESSIBLE_BUT_NO_DATA"),
            ("render", "render-api", "ACCESSIBLE_BUT_NO_DATA"),
            ("vercel", "acme-preview", "ACCESSIBLE_BUT_NO_DATA"),
        ]
        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row is None
    finally:
        con.close()


def test_sweep_pending_cloud_asset_validations_processes_pages_managed_hosting_assets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (?, ?, ?, ?)
            """,
            [
                (1001, "github_pages", "acme.github.io", "artifact_url_extract"),
                (1001, "gitlab_pages", "security.gitlab.io", "artifact_url_extract"),
                (1001, "cloudflare_pages", "acme-pages", "artifact_url_extract"),
                (1001, "cloudflare_worker", "worker.acme.workers.dev", "artifact_url_extract"),
                (1001, "cloudflare_r2", "pub-acme.r2.dev", "artifact_url_extract"),
                (1001, "cloudflare_d1", "acme-d1-prod", "artifact_cloudflare_config"),
                (1001, "cloudflare_kv", "acme-kv-cache", "artifact_cloudflare_config"),
            ],
        )
        con.commit()
    finally:
        con.close()

    class _ManagedPagesClient:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            del args, kwargs

        def __enter__(self) -> "_ManagedPagesClient":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            del exc_type, exc, tb

        def head(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
            del kwargs
            if url in {
                "https://acme.github.io",
                "https://security.gitlab.io",
                "https://acme-pages.pages.dev",
                "https://worker.acme.workers.dev",
                "https://pub-acme.r2.dev",
            }:
                return _FakeResponse(200, "", {"content-type": "text/html"})
            return _FakeResponse(404, "missing", {"content-type": "text/plain"})

        def get(self, url: str, **kwargs) -> _FakeResponse:  # noqa: ANN003
            return self.head(url, **kwargs)

    monkeypatch.setattr(cloud_validate.httpx, "Client", _ManagedPagesClient)
    summary = cloud_validate.sweep_pending_cloud_asset_validations(
        1001,
        db_path,
        limit=10,
        max_workers=1,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 7
    assert summary["succeeded"] == 7
    assert summary["failed"] == 0
    assert summary["status_counts"]["ACCESSIBLE_BUT_NO_DATA"] == 5
    assert summary["status_counts"]["UNSUPPORTED"] == 2
    assert [(item["asset_type"], item["identifier"]) for item in summary["results"]] == [
        ("github_pages", "acme.github.io"),
        ("gitlab_pages", "security.gitlab.io"),
        ("cloudflare_pages", "acme-pages"),
        ("cloudflare_worker", "worker.acme.workers.dev"),
        ("cloudflare_r2", "pub-acme.r2.dev"),
        ("cloudflare_d1", "acme-d1-prod"),
        ("cloudflare_kv", "acme-kv-cache"),
    ]

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert validation_rows == [
            ("cloudflare_d1", "acme-d1-prod", "UNSUPPORTED"),
            ("cloudflare_kv", "acme-kv-cache", "UNSUPPORTED"),
            ("cloudflare_pages", "acme-pages", "ACCESSIBLE_BUT_NO_DATA"),
            ("cloudflare_r2", "pub-acme.r2.dev", "ACCESSIBLE_BUT_NO_DATA"),
            ("cloudflare_worker", "worker.acme.workers.dev", "ACCESSIBLE_BUT_NO_DATA"),
            ("github_pages", "acme.github.io", "ACCESSIBLE_BUT_NO_DATA"),
            ("gitlab_pages", "security.gitlab.io", "ACCESSIBLE_BUT_NO_DATA"),
        ]

        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row is None
    finally:
        con.close()


def test_sweep_pending_cloud_asset_validations_processes_aws_client_references(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, provider_identifier, source)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "aws_cognito_user_pool",
                    "us-east-1_abcd12345",
                    "us-east-1_AbCd12345",
                    "artifact_amplify_client_config",
                ),
                (
                    1001,
                    "aws_appsync_api",
                    "us-east-1/abc123456789",
                    "us-east-1/abc123456789",
                    "artifact_amplify_client_config",
                ),
                (
                    1001,
                    "aws_cognito_identity_pool",
                    "us-east-1:11111111-2222-3333-4444-555555555555",
                    "us-east-1:11111111-2222-3333-4444-555555555555",
                    "artifact_amplify_client_config",
                ),
                (
                    1001,
                    "aws_pinpoint_app",
                    "us-east-1/pinpoint123",
                    "us-east-1/pinpoint123",
                    "artifact_amplify_client_config",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    _AwsClientReferenceClient.calls.clear()
    _AwsClientReferenceClient.kwargs_seen.clear()
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AwsClientReferenceClient)
    summary = cloud_validate.sweep_pending_cloud_asset_validations(
        1001,
        db_path,
        limit=10,
        max_workers=1,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 4
    assert summary["succeeded"] == 4
    assert summary["failed"] == 0
    assert summary["status_counts"] == {
        "ACCESSIBLE_BUT_NO_DATA": 2,
        "UNSUPPORTED": 2,
    }
    assert [
        (item["asset_type"], item["identifier"], item["provider_identifier"], item["validation_status"])
        for item in summary["results"]
    ] == [
        (
            "aws_cognito_user_pool",
            "us-east-1_abcd12345",
            "us-east-1_AbCd12345",
            "ACCESSIBLE_BUT_NO_DATA",
        ),
        (
            "aws_appsync_api",
            "us-east-1/abc123456789",
            "us-east-1/abc123456789",
            "ACCESSIBLE_BUT_NO_DATA",
        ),
        (
            "aws_cognito_identity_pool",
            "us-east-1:11111111-2222-3333-4444-555555555555",
            "us-east-1:11111111-2222-3333-4444-555555555555",
            "UNSUPPORTED",
        ),
        (
            "aws_pinpoint_app",
            "us-east-1/pinpoint123",
            "us-east-1/pinpoint123",
            "UNSUPPORTED",
        ),
    ]

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, identifier, provider_identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY id
            """
        ).fetchall()
        assert validation_rows == [
            ("aws_cognito_user_pool", "us-east-1_abcd12345", "us-east-1_AbCd12345", "ACCESSIBLE_BUT_NO_DATA"),
            ("aws_appsync_api", "us-east-1/abc123456789", "us-east-1/abc123456789", "ACCESSIBLE_BUT_NO_DATA"),
            (
                "aws_cognito_identity_pool",
                "us-east-1:11111111-2222-3333-4444-555555555555",
                "us-east-1:11111111-2222-3333-4444-555555555555",
                "UNSUPPORTED",
            ),
            ("aws_pinpoint_app", "us-east-1/pinpoint123", "us-east-1/pinpoint123", "UNSUPPORTED"),
        ]
        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row is None
    finally:
        con.close()
    assert _AwsClientReferenceClient.calls == [
        "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCd12345/.well-known/openid-configuration",
        "https://abc123456789.appsync-api.us-east-1.amazonaws.com/graphql",
    ]
    assert _AwsClientReferenceClient.kwargs_seen == [{}, {}]


def test_run_cloud_asset_validate_marks_synthetic_firebase_response_as_honeypot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _FirebaseHoneypotClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "firebase",
        "acme-firebase-prod",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "HONEYPOT_SUSPECTED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("HONEYPOT_SUSPECTED",)

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_structured_firebase_error_payload_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _FirebaseJsonErrorClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "firebase",
        "acme-firebase-prod",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "UNVERIFIED"
    assert "Structured error payload" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("UNVERIFIED", "firebase_database_shallow_read")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_does_not_treat_low_signal_firebase_shallow_keys_as_validated_data(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _FirebaseMetadataOnlyShallowClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "firebase",
        "acme-firebase-prod",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert result["validation_method"] == "firebase_database_shallow_read"
    assert "low-signal scaffold" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "firebase_database_shallow_read")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_requires_live_child_data_after_firebase_shallow_key_probe(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _FirebaseShallowKeyOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "firebase",
        "acme-firebase-prod",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert result["validation_method"] == "firebase_database_shallow_read"
    assert "no live child-node data payload was confirmed" in str(result["notes"]).lower()

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "firebase_database_shallow_read")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_synthetic_supabase_response_as_honeypot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseHoneypotClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "supabase",
        "acme-workspace",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "HONEYPOT_SUSPECTED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("HONEYPOT_SUSPECTED",)
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_structured_supabase_error_payload_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseJsonErrorClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "supabase",
        "acme-workspace",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "UNVERIFIED"
    assert "Structured error payload" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("UNVERIFIED", "supabase_settings")
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_html_supabase_landing_page_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseHtmlLandingClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "supabase",
        "acme-workspace",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "UNVERIFIED"
    assert "non-JSON" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("UNVERIFIED", "supabase_settings")
    finally:
        con.close()


def test_run_cloud_asset_validate_does_not_treat_supabase_settings_metadata_as_validated_access(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseSettingsOnlySecretClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "supabase",
        "acme-workspace",
        db_path,
        secret="sb_secret_token",
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert result["validation_method"] == "supabase_rest_root"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "supabase_rest_root")
    finally:
        con.close()


def test_run_cloud_asset_validate_requires_supabase_rest_access_for_validated_status(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseRestAccessClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "supabase",
        "acme-workspace",
        db_path,
        secret="sb_secret_token",
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "VALIDATED"
    assert result["validation_method"] == "supabase_rest_root"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("VALIDATED", "supabase_rest_root")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_supabase_low_signal_rows(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseRestLowSignalRowClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "supabase",
        "acme-workspace",
        db_path,
        secret="sb_secret_token",
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert result["validation_method"] == "supabase_rest_root"
    assert "low-signal row metadata" in str(result["notes"]).lower()

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "supabase_rest_root")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_supabase_demo_rows_as_honeypot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseRestSyntheticRowClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "supabase",
        "acme-workspace",
        db_path,
        secret="sb_secret_token",
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "HONEYPOT_SUSPECTED"
    assert result["validation_method"] == "supabase_rest_root"
    assert "synthetic or demo-only" in str(result["notes"]).lower()

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("HONEYPOT_SUSPECTED", "supabase_rest_root")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_supabase_reserved_example_domain_row_as_honeypot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseRestReservedExampleRowClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "supabase",
        "acme-workspace",
        db_path,
        secret="sb_secret_token",
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "HONEYPOT_SUSPECTED"
    assert result["validation_method"] == "supabase_rest_root"
    assert "synthetic or demo-only" in str(result["notes"]).lower()

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("HONEYPOT_SUSPECTED", "supabase_rest_root")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_does_not_treat_supabase_rest_schema_as_validated_data_access(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseRestSchemaOnlySecretClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "supabase",
        "acme-workspace",
        db_path,
        secret="sb_secret_token",
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert result["validation_method"] == "supabase_rest_root"
    assert "schema metadata" in str(result["notes"]).lower()

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "supabase_rest_root")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_does_not_treat_supabase_rest_catalog_as_validated_data_access(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseRestCatalogOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "supabase",
        "acme-workspace",
        db_path,
        secret="sb_secret_token",
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert result["validation_method"] == "supabase_rest_root"
    assert "catalog metadata" in str(result["notes"]).lower()

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "supabase_rest_root")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_public_supabase_rest_data_validated_without_secret(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _SupabaseRestAccessClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "supabase",
        "acme-workspace",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "VALIDATED"
    assert result["validation_method"] == "supabase_rest_root"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("VALIDATED", "supabase_rest_root")

        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row == ("HIGH", "Validated Supabase data exposure")
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_synthetic_s3_listing_as_honeypot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3HoneypotClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "HONEYPOT_SUSPECTED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("HONEYPOT_SUSPECTED", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_single_synthetic_s3_object_as_honeypot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3SingleObjectDecoyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "HONEYPOT_SUSPECTED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("HONEYPOT_SUSPECTED", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_scaffold_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3ScaffoldOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "placeholder objects" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_package_metadata_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3PackageMetadataOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "package/repository metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_runtime_metadata_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3RuntimeMetadataOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "runtime metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_filesystem_metadata_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3FilesystemMetadataOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "filesystem metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_api_documentation_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3ApiDocumentationOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "API documentation metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_keeps_s3_api_docs_plus_data_validated(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3ApiDocsPlusDataClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "VALIDATED"
    assert "object metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("VALIDATED", "s3_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_static_site_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3StaticSiteScaffoldClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_public_metadata_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3PublicMetadataStaticSiteClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_domain_verification_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(
        cloud_validate.httpx,
        "Client",
        _S3DomainVerificationStaticSiteClient,
    )

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_framework_static_site_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3FrameworkStaticSiteClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_hosting_config_static_site_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3HostingConfigStaticSiteClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_plain_static_asset_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3PlainStaticAssetSiteClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_well_known_static_site_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3WellKnownStaticSiteClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_identity_discovery_metadata_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3IdentityDiscoveryMetadataClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_acme_challenge_static_site_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3WellKnownChallengeStaticSiteClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_marketing_page_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3MarketingPageStaticSiteClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_sitemap_feed_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3SitemapFeedStaticSiteClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_classifies_structured_s3_error_payload(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3StructuredErrorClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "UNVERIFIED"
    assert "Structured error payload" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("UNVERIFIED", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_non_200_s3_structured_not_found_dead(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3ForbiddenNoSuchBucketClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "DEAD"
    assert result["validation_method"] == "s3_list_bucket"
    assert "not found" in str(result["notes"]).lower()

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("DEAD", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_s3_head_only_success_without_listing_proof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3HeadOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert result["validation_method"] == "s3_head_probe"
    assert "no follow-up listing data could be confirmed" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "s3_head_probe")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_s3_validator_paces_and_retries_rate_limited_head_probe(monkeypatch) -> None:
    sleeps: list[float] = []
    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setenv("FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS", "0.25")
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS", "9")
    monkeypatch.setenv("FORGE_KEY_VALIDATION_MAX_RETRY_AFTER_SECONDS", "1")
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setattr(http_pacing.time, "sleep", lambda seconds: sleeps.append(float(seconds)))
    _S3RateLimitThenListClient.instances = []
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3RateLimitThenListClient)

    result = cloud_validate.S3Validator().validate("acme-public-assets")

    assert result.validation_status == "VALIDATED"
    assert result.validation_method == "s3_list_bucket"
    assert sleeps == [0.25, 1.0, 0.25, 1.0, 0.25]
    assert [call[0] for call in _S3RateLimitThenListClient.instances[0].calls] == [
        "HEAD",
        "HEAD",
        "GET",
    ]


def test_run_cloud_asset_validate_marks_unexpected_s3_success_payload_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3UnexpectedSuccessPayloadClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "aws_s3",
        "acme-public-assets",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "UNVERIFIED"
    assert result["validation_method"] == "s3_list_bucket"
    assert "unexpected success payload" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("UNVERIFIED", "s3_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_persists_gcs_bucket_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "VALIDATED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("gcs", "acme-gcs-public", "VALIDATED")

        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row == ("HIGH", "Validated public Google Cloud Storage bucket listing exposure")
    finally:
        con.close()


def test_run_cloud_asset_validate_persists_gcs_json_bucket_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSJsonListingClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "VALIDATED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("gcs", "acme-gcs-public", "VALIDATED")

        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row == ("HIGH", "Validated public Google Cloud Storage bucket listing exposure")
    finally:
        con.close()


def test_run_cloud_asset_validate_persists_digitalocean_spaces_bucket_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _DOSpacesClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "do_spaces",
        "nyc3/acme-space-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "VALIDATED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("do_spaces", "nyc3/acme-space-public", "VALIDATED")

        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row == ("HIGH", "Validated public DigitalOcean Spaces bucket listing exposure")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_digitalocean_spaces_static_site_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _DOSpacesStaticSiteScaffoldClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "do_spaces",
        "nyc3/acme-space-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "do_spaces_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_digitalocean_spaces_api_documentation_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _DOSpacesApiDocumentationOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "do_spaces",
        "nyc3/acme-space-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "API documentation metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "do_spaces_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_gcs_scaffold_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSScaffoldOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "placeholder objects" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "gcs_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_gcs_package_metadata_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSPackageMetadataOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "package/repository metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "gcs_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_gcs_json_metadata_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSJsonMetadataOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "package/repository metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "gcs_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_gcs_api_documentation_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSApiDocumentationOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "API documentation metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "gcs_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_gcs_json_api_documentation_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSJsonApiDocumentationOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "API documentation metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "gcs_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_gcs_filesystem_metadata_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSFilesystemMetadataOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "filesystem metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "gcs_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_single_synthetic_gcs_object_as_honeypot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSSingleObjectDecoyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "HONEYPOT_SUSPECTED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("HONEYPOT_SUSPECTED", "gcs_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_json_single_synthetic_gcs_object_as_honeypot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSJsonSingleObjectDecoyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "HONEYPOT_SUSPECTED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("HONEYPOT_SUSPECTED", "gcs_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_gcs_static_site_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSStaticSiteScaffoldClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "gcs_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_gcs_acme_challenge_static_site_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSWellKnownChallengeStaticSiteClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "gcs_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_html_gcs_landing_page_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSHtmlLandingClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "UNVERIFIED"
    assert "HTML content" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("UNVERIFIED", "gcs_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_classifies_structured_gcs_error_payload(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSErrorXmlClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "Structured error payload" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "gcs_list_bucket")
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_non_200_gcs_structured_not_found_dead(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSForbiddenNotFoundJsonClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "DEAD"
    assert result["validation_method"] == "gcs_list_bucket"
    assert "not found" in str(result["notes"]).lower()

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("DEAD", "gcs_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_unexpected_gcs_success_payload_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _GCSUnexpectedSuccessPayloadClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "gcs",
        "acme-gcs-public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "UNVERIFIED"
    assert result["validation_method"] == "gcs_list_bucket"
    assert "unexpected success payload" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("UNVERIFIED", "gcs_list_bucket")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_persists_azure_blob_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AzureBlobClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "azure_blob",
        "acmeblob/public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "VALIDATED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("azure_blob", "acmeblob/public", "VALIDATED")

        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding_row == ("HIGH", "Validated public Azure Blob container listing exposure")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_azure_blob_scaffold_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AzureBlobScaffoldOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "azure_blob",
        "acmeblob/public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "placeholder objects" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "azure_blob_list_container")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_azure_blob_package_metadata_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AzureBlobPackageMetadataOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "azure_blob",
        "acmeblob/public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "package/repository metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "azure_blob_list_container")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_azure_blob_filesystem_metadata_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AzureBlobFilesystemMetadataOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "azure_blob",
        "acmeblob/public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "filesystem metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "azure_blob_list_container")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_single_synthetic_azure_blob_object_as_honeypot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AzureBlobSingleObjectDecoyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "azure_blob",
        "acmeblob/public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "HONEYPOT_SUSPECTED"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("HONEYPOT_SUSPECTED", "azure_blob_list_container")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_azure_blob_api_documentation_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AzureBlobApiDocumentationOnlyClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "azure_blob",
        "acmeblob/public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "API documentation metadata" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "azure_blob_list_container")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_azure_blob_static_site_only_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AzureBlobStaticSiteScaffoldClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "azure_blob",
        "acmeblob/public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "azure_blob_list_container")
    finally:
        con.close()


def test_run_cloud_asset_validate_downgrades_azure_blob_acme_challenge_static_site_listing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(
        cloud_validate.httpx,
        "Client",
        _AzureBlobWellKnownChallengeStaticSiteClient,
    )

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "azure_blob",
        "acmeblob/public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"
    assert "static-site assets" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("ACCESSIBLE_BUT_NO_DATA", "azure_blob_list_container")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_classifies_structured_azure_error_payload(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AzureBlobErrorXmlClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "azure_blob",
        "acmeblob/public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "DEAD"
    assert "Structured error payload" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("DEAD", "azure_blob_list_container")
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_non_200_azure_structured_not_found_dead(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AzureBlobConflictNotFoundClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "azure_blob",
        "acmeblob/public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "DEAD"
    assert result["validation_method"] == "azure_blob_list_container"
    assert "not found" in str(result["notes"]).lower()

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("DEAD", "azure_blob_list_container")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_run_cloud_asset_validate_marks_unexpected_azure_blob_success_payload_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _AzureBlobUnexpectedSuccessPayloadClient)

    result = cloud_validate.run_cloud_asset_validate(
        1001,
        "azure_blob",
        "acmeblob/public",
        db_path,
    )

    assert result["status"] == "success"
    assert result["validation_status"] == "UNVERIFIED"
    assert result["validation_method"] == "azure_blob_list_container"
    assert "unexpected success payload" in str(result["notes"])

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("UNVERIFIED", "azure_blob_list_container")

        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_sweep_pending_cloud_validations_processes_supported_key_rows(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, validation_state)
            VALUES
                (7, 1001, 'acme-firebase-prod', 'firebase', 'firebase_web_config', 'crawler',
                 'https://acme-firebase-prod.firebaseapp.com/__/firebase/init.json',
                 'webapp', 'AIza...7890', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(cloud_validate.httpx, "Client", _FirebaseClient)
    summary = cloud_validate.sweep_pending_cloud_validations(1001, db_path, limit=10)

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["ACCESSIBLE_BUT_NO_DATA"] == 1
    assert summary["results"][0]["key_id"] == 7
    assert summary["results"][0]["validation_status"] == "ACCESSIBLE_BUT_NO_DATA"

    con = sqlite3.connect(db_path)
    try:
        key_state = con.execute(
            "SELECT validation_state FROM key_scanner_findings WHERE id=7"
        ).fetchone()[0]
        assert key_state == "UNCONFIRMED"
    finally:
        con.close()


def test_sweep_pending_cloud_validations_batches_multiple_rows_with_ordered_results(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, validation_state)
            VALUES
                (?, 1001, ?, ?, ?, 'crawler', ?, 'webapp', ?, 'UNCONFIRMED')
            """,
            [
                (
                    11,
                    "acme-firebase-prod",
                    "firebase",
                    "firebase_web_config",
                    "https://acme-firebase-prod.firebaseapp.com/__/firebase/init.json",
                    "AIza...7890",
                ),
                (
                    12,
                    "https://acme-workspace.supabase.co",
                    "supabase",
                    "supabase_mobile_config",
                    "https://acme-workspace.supabase.co/rest/v1/",
                    "sb_publishable_1234",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(cloud_validate.httpx, "Client", _MixedBatchClient)
    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=4,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 2
    assert summary["succeeded"] == 2
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["status_counts"]["HONEYPOT_SUSPECTED"] == 1
    assert [row["key_id"] for row in summary["results"]] == [11, 12]
    assert [row["validation_status"] for row in summary["results"]] == [
        "VALIDATED",
        "HONEYPOT_SUSPECTED",
    ]

    con = sqlite3.connect(db_path)
    try:
        key_rows = con.execute(
            """
            SELECT id, validation_state
            FROM key_scanner_findings
            WHERE id IN (11, 12)
            ORDER BY id
            """
        ).fetchall()
        assert key_rows == [
            (11, "ACTIVE"),
            (12, "UNCONFIRMED"),
        ]
    finally:
        con.close()


def test_sweep_pending_cloud_validations_defaults_to_sequential_key_workers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, validation_state)
            VALUES
                (?, 1001, ?, 'firebase', 'firebase_web_config', 'crawler', ?, 'webapp', ?, 'UNCONFIRMED')
            """,
            [
                (31, "asset-one", "https://asset-one.firebaseapp.com/__/firebase/init.json", "AIza...one"),
                (32, "asset-two", "https://asset-two.firebaseapp.com/__/firebase/init.json", "AIza...two"),
                (33, "asset-three", "https://asset-three.firebaseapp.com/__/firebase/init.json", "AIza...three"),
            ],
        )
        con.commit()
    finally:
        con.close()

    active = 0
    peak = 0
    lock = threading.Lock()
    seen: list[int] = []

    def _fake_validate_key_row_payload(
        row_payload: dict,
        *,
        registry: cloud_validate.CloudValidatorRegistry,
        db_path: Path,
    ) -> tuple[int, int, cloud_validate.CloudValidationResult]:
        nonlocal active, peak
        del registry, db_path
        key_id = int(row_payload["id"])
        seen.append(key_id)
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.02)
            return (
                key_id,
                int(row_payload["engagement_id"]),
                cloud_validate.CloudValidationResult(
                    asset_type=str(row_payload["service"]),
                    identifier=str(row_payload["domain"]),
                    validation_status="ACCESSIBLE_BUT_NO_DATA",
                    validation_method="test_key_probe",
                    evidence="scaffold only",
                ),
            )
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        cloud_validate,
        "_validate_key_row_payload",
        _fake_validate_key_row_payload,
    )

    summary = cloud_validate.sweep_pending_cloud_validations(1001, db_path, limit=10)

    assert summary["status"] == "success"
    assert summary["attempted"] == 3
    assert [row["key_id"] for row in summary["results"]] == [31, 32, 33]
    assert seen == [31, 32, 33]
    assert peak == 1


def test_sweep_pending_cloud_validations_derives_supabase_identifier_from_key_only_secret(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (?, 1001, ?, ?, ?, 'artifact', ?, ?, ?, ?, 'UNCONFIRMED')
            """,
            [
                (
                    13,
                    "acme-firebase-prod",
                    "firebase",
                    "firebase_web_config",
                    "https://acme-firebase-prod.firebaseapp.com/__/firebase/init.json",
                    "webapp",
                    "AIza...7890",
                    None,
                ),
                (
                    14,
                    "",
                    "supabase",
                    "supabase_mobile_config",
                    "",
                    "bundle.js",
                    "sb_publishable",
                    "ciphertext-placeholder",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(
        cloud_validate,
        "_decrypt_secret",
        lambda value: (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFjbWUtd29ya3NwYWNlIiwicm9sZSI6ImFub24ifQ."
            "signature999"
            if value
            else None
        ),
    )
    monkeypatch.setattr(cloud_validate.httpx, "Client", _MixedBatchClient)
    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=4,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 2
    assert summary["succeeded"] == 2
    assert summary["failed"] == 0
    assert [row["key_id"] for row in summary["results"]] == [13, 14]
    assert [row["identifier"] for row in summary["results"]] == [
        "acme-firebase-prod",
        "acme-workspace",
    ]
    assert [row["validation_status"] for row in summary["results"]] == [
        "VALIDATED",
        "HONEYPOT_SUSPECTED",
    ]

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY identifier
            """
        ).fetchall()
        assert validation_rows == [
            ("firebase", "acme-firebase-prod", "VALIDATED"),
            ("supabase", "acme-workspace", "HONEYPOT_SUSPECTED"),
        ]
    finally:
        con.close()


def test_run_cloud_asset_validate_batch_persists_mixed_results(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _MixedBatchClient)

    result = cloud_validate.run_cloud_asset_validate_batch(
        1001,
        [
            ("firebase", "acme-firebase-prod"),
            ("supabase", "acme-workspace"),
        ],
        db_path,
        max_workers=2,
    )

    assert result["status"] == "success"
    assert result["attempted"] == 2
    assert result["succeeded"] == 2
    assert result["status_counts"]["VALIDATED"] == 1
    assert result["status_counts"]["HONEYPOT_SUSPECTED"] == 1
    assert [row["identifier"] for row in result["results"]] == [
        "acme-firebase-prod",
        "acme-workspace",
    ]

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY identifier
            """
        ).fetchall()
        assert validation_rows == [
            ("firebase", "acme-firebase-prod", "VALIDATED"),
            ("supabase", "acme-workspace", "HONEYPOT_SUSPECTED"),
        ]

        finding_rows = con.execute(
            """
            SELECT title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY title
            """
        ).fetchall()
        assert finding_rows == [("Validated Firebase data exposure",)]
    finally:
        con.close()


@pytest.mark.parametrize("max_workers", [1, 2])
def test_run_cloud_asset_validate_batch_persists_validator_exception_receipts(
    tmp_path: Path,
    monkeypatch,
    max_workers: int,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    def _fake_probe(
        asset_type: str,
        identifier: str,
        *,
        secret: str | None = None,
    ) -> cloud_validate.CloudValidationResult:
        assert secret is None
        if identifier == "broken-project":
            raise RuntimeError("raw secret should not persist")
        return cloud_validate.CloudValidationResult(
            asset_type=asset_type,
            identifier=identifier,
            validation_status="ACCESSIBLE_BUT_NO_DATA",
            validation_method="stub_reachability",
            evidence="safe stub proof",
            provider_identifier=identifier,
        )

    monkeypatch.setattr(cloud_validate, "_probe_cloud_asset_result", _fake_probe)

    result = cloud_validate.run_cloud_asset_validate_batch(
        1001,
        [
            ("firebase", "broken-project"),
            ("supabase", "working-project"),
        ],
        db_path,
        max_workers=max_workers,
    )

    assert result["status"] == "success"
    assert result["attempted"] == 2
    assert result["succeeded"] == 1
    assert result["failed"] == 1
    assert result["status_counts"] == {
        "ACCESSIBLE_BUT_NO_DATA": 1,
        "UNVERIFIED": 1,
    }
    assert [row["identifier"] for row in result["results"]] == [
        "broken-project",
        "working-project",
    ]
    failed = result["results"][0]
    assert failed["validation_status"] == "UNVERIFIED"
    assert failed["validation_method"] == "validator_exception"
    assert failed["notes"] == "validator_exception:RuntimeError"
    assert "raw secret" not in json.dumps(result)

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method, notes
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY identifier
            """
        ).fetchall()
        assert rows == [
            (
                "firebase",
                "broken-project",
                "UNVERIFIED",
                "validator_exception",
                "validator_exception:RuntimeError",
            ),
            (
                "supabase",
                "working-project",
                "ACCESSIBLE_BUT_NO_DATA",
                "stub_reachability",
                "",
            ),
        ]
    finally:
        con.close()


def test_run_cloud_asset_validate_batch_defaults_to_sequential_validation_workers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    active = 0
    peak = 0
    lock = threading.Lock()
    seen: list[str] = []

    def _fake_probe(
        asset_type: str,
        identifier: str,
        *,
        secret: str | None = None,
    ) -> cloud_validate.CloudValidationResult:
        nonlocal active, peak
        assert secret is None
        seen.append(identifier)
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.02)
            return cloud_validate.CloudValidationResult(
                asset_type=asset_type,
                identifier=identifier,
                validation_status="ACCESSIBLE_BUT_NO_DATA",
                validation_method="test_probe",
                evidence="scaffold only",
            )
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(cloud_validate, "_probe_cloud_asset_result", _fake_probe)

    result = cloud_validate.run_cloud_asset_validate_batch(
        1001,
        [
            ("firebase", "asset-one"),
            ("supabase", "asset-two"),
            ("aws_s3", "asset-three"),
        ],
        db_path,
    )

    assert result["status"] == "success"
    assert [row["identifier"] for row in result["results"]] == [
        "asset-one",
        "asset-two",
        "asset-three",
    ]
    assert seen == ["asset-one", "asset-two", "asset-three"]
    assert peak == 1


def test_run_cloud_asset_validate_batch_default_workers_can_be_raised_by_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setenv("FORGE_VALIDATION_MAX_WORKERS", "2")

    active = 0
    peak = 0
    lock = threading.Lock()

    def _fake_probe(
        asset_type: str,
        identifier: str,
        *,
        secret: str | None = None,
    ) -> cloud_validate.CloudValidationResult:
        nonlocal active, peak
        assert secret is None
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.02)
            return cloud_validate.CloudValidationResult(
                asset_type=asset_type,
                identifier=identifier,
                validation_status="ACCESSIBLE_BUT_NO_DATA",
                validation_method="test_probe",
                evidence="scaffold only",
            )
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(cloud_validate, "_probe_cloud_asset_result", _fake_probe)

    result = cloud_validate.run_cloud_asset_validate_batch(
        1001,
        [
            ("firebase", "asset-one"),
            ("supabase", "asset-two"),
            ("aws_s3", "asset-three"),
        ],
        db_path,
    )

    assert result["status"] == "success"
    assert peak == 2


def test_run_cloud_asset_validate_batch_emits_progress_metrics(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _MixedBatchClient)

    progress_events: list[tuple[str, dict[str, object]]] = []
    result = cloud_validate.run_cloud_asset_validate_batch(
        1001,
        [
            ("firebase", "acme-firebase-prod"),
            ("supabase", "acme-workspace"),
        ],
        db_path,
        max_workers=2,
        progress_label="2.J cloud validation",
        progress_callback=lambda label, metrics: progress_events.append((label, dict(metrics))),
    )

    assert result["status"] == "success"
    assert progress_events
    assert progress_events[0][0] == "2.J cloud validation"
    assert int(progress_events[0][1]["completed"]) == 0
    assert int(progress_events[-1][1]["completed"]) == 2
    assert int(progress_events[-1][1]["total"]) == 2
    assert int(progress_events[-1][1]["queue_depth"]) == 0
    assert float(progress_events[-1][1]["eta_seconds"] or 0.0) == 0.0


def test_run_cloud_asset_validate_batch_parallelizes_scope_gate_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setattr(cloud_validate.httpx, "Client", _MixedBatchClient)

    active_scope_checks = 0
    max_active_scope_checks = 0
    active_lock = threading.Lock()
    denied_callbacks: list[tuple[str, str, str]] = []

    def _scope_checker(asset_type: str, identifier: str) -> bool:
        nonlocal active_scope_checks, max_active_scope_checks
        del asset_type
        with active_lock:
            active_scope_checks += 1
            max_active_scope_checks = max(max_active_scope_checks, active_scope_checks)
        time.sleep(0.05)
        with active_lock:
            active_scope_checks -= 1
        return identifier in {"acme-firebase-prod", "acme-workspace"}

    result = cloud_validate.run_cloud_asset_validate_batch(
        1001,
        [
            ("firebase", "acme-firebase-prod"),
            ("firebase", "denied-firebase"),
            ("supabase", "acme-workspace"),
            ("supabase", "denied-workspace"),
        ],
        db_path,
        max_workers=4,
        scope_checker=_scope_checker,
        scope_denied_callback=lambda asset_type, identifier, reason: denied_callbacks.append(
            (asset_type, identifier, reason)
        ),
    )

    assert max_active_scope_checks > 1
    assert denied_callbacks == [
        ("firebase", "denied-firebase", "scope_manifest_denied"),
        ("supabase", "denied-workspace", "scope_manifest_denied"),
    ]
    assert result["attempted"] == 4
    assert result["succeeded"] == 4
    assert result["failed"] == 0
    assert result["status_counts"]["VALIDATED"] == 1
    assert result["status_counts"]["HONEYPOT_SUSPECTED"] == 1
    assert result["status_counts"]["UNVERIFIED"] == 2
    assert [row["identifier"] for row in result["results"]] == [
        "acme-firebase-prod",
        "denied-firebase",
        "acme-workspace",
        "denied-workspace",
    ]


def test_extract_identifier_supports_alternate_storage_url_forms() -> None:
    s3_hosted = {
        "domain": "https://acme-site-bucket.s3-website-us-east-1.amazonaws.com/index.html",
        "source_url": "",
        "repo_name": "",
        "validation_detail": "",
    }
    s3_path_style = {
        "domain": "",
        "source_url": "https://s3-website-us-east-1.amazonaws.com/acme-path-bucket/index.html",
        "repo_name": "",
        "validation_detail": "",
    }
    gcs_browser = {
        "domain": "https://storage.cloud.google.com/acme-browser-bucket/reports/final.pdf",
        "source_url": "",
        "repo_name": "",
        "validation_detail": "",
    }
    firebase_storage = {
        "domain": "https://firebasestorage.googleapis.com/v0/b/acme-firestorage.appspot.com/o/reports%2Ffinal.pdf?alt=media",
        "source_url": "",
        "repo_name": "",
        "validation_detail": "",
    }
    azure_dfs = {
        "domain": "https://acmedatalake.dfs.core.windows.net/raw/reports/final.json",
        "source_url": "",
        "repo_name": "",
        "validation_detail": "",
    }
    azure_dfs_source = {
        "domain": "",
        "source_url": "https://sourcedatalake.dfs.core.windows.net/events/year=2026/final.json",
        "repo_name": "",
        "validation_detail": "",
    }
    azure_static = {
        "domain": "https://acmestatic.z22.web.core.windows.net/index.html",
        "source_url": "",
        "repo_name": "",
        "validation_detail": "",
    }
    azure_static_source = {
        "domain": "",
        "source_url": "https://sourcestatic.web.core.windows.net/assets/app.js",
        "repo_name": "",
        "validation_detail": "",
    }

    assert cloud_validate._extract_identifier("aws_s3", s3_hosted) == "acme-site-bucket"
    assert cloud_validate._extract_identifier("aws_s3", s3_path_style) == "acme-path-bucket"
    assert cloud_validate._extract_identifier("gcs", gcs_browser) == "acme-browser-bucket"
    assert cloud_validate._extract_identifier("gcs", firebase_storage) == "acme-firestorage.appspot.com"
    assert cloud_validate._extract_identifier("azure_blob", azure_dfs) == "acmedatalake/raw"
    assert cloud_validate._extract_identifier("azure_blob", azure_dfs_source) == "sourcedatalake/events"
    assert cloud_validate._extract_identifier("azure_blob", azure_static) == "acmestatic/$web"
    assert cloud_validate._extract_identifier("azure_blob", azure_static_source) == "sourcestatic/$web"


def test_sweep_pending_cloud_asset_validations_processes_unvalidated_assets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (?, ?, ?, ?)
            """,
            [
                (1001, "aws_s3", "acme-public-assets", "artifact_s3_uri"),
                (1001, "firebase", "acme-firebase-prod", "firebase_extract"),
            ],
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'ACCESSIBLE_BUT_NO_DATA', 'firebase_init_json', 200, '{"projectId":"acme-firebase-prod"}', 'Already checked')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(cloud_validate.httpx, "Client", _S3HeadClient)
    summary = cloud_validate.sweep_pending_cloud_asset_validations(
        1001,
        db_path,
        limit=10,
        max_workers=4,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["identifier"] == "acme-public-assets"
    assert summary["results"][0]["asset_type"] == "aws_s3"

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert validation_rows == [
            ("aws_s3", "acme-public-assets", "VALIDATED"),
            ("firebase", "acme-firebase-prod", "ACCESSIBLE_BUT_NO_DATA"),
        ]

        finding_row = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001 AND target_url='aws_s3://acme-public-assets'
            """
        ).fetchone()
        assert finding_row == ("HIGH", "Validated public S3 bucket listing exposure")
    finally:
        con.close()


def test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (?, ?, ?, ?)
            """,
            [
                (1001, "supabase", "allowed", "html_extract"),
                (1001, "firebase", "denied", "html_extract"),
            ],
        )
        con.commit()
    finally:
        con.close()

    validated_batches: list[list[tuple[str, str]]] = []
    denied_callbacks: list[tuple[str, str, str]] = []

    def _fake_validate_batch(engagement_id, assets, db_path, **kwargs):  # noqa: ANN001
        del engagement_id, db_path, kwargs
        normalized_assets = [(str(asset[0]), str(asset[1])) for asset in assets]
        validated_batches.append(normalized_assets)
        return {
            "status": "success",
            "engagement_id": 1001,
            "attempted": len(normalized_assets),
            "succeeded": len(normalized_assets),
            "failed": 0,
            "status_counts": {"VALIDATED": len(normalized_assets)},
            "results": [
                {
                    "status": "success",
                    "engagement_id": 1001,
                    "asset_type": asset_type,
                    "identifier": identifier,
                    "validation_status": "VALIDATED",
                    "validation_method": "stub",
                }
                for asset_type, identifier in normalized_assets
            ],
        }

    monkeypatch.setattr(cloud_validate, "run_cloud_asset_validate_batch", _fake_validate_batch)

    summary = cloud_validate.sweep_pending_cloud_asset_validations(
        1001,
        db_path,
        limit=10,
        max_workers=2,
        scope_checker=lambda asset_type, identifier: identifier == "allowed",
        scope_denied_callback=lambda asset_type, identifier, reason: denied_callbacks.append(
            (asset_type, identifier, reason)
        ),
    )

    assert validated_batches == [[("supabase", "allowed")]]
    assert denied_callbacks == [("firebase", "denied", "scope_manifest_denied")]
    assert summary["attempted"] == 2
    assert summary["succeeded"] == 2
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["status_counts"]["UNVERIFIED"] == 1

    con = sqlite3.connect(db_path)
    try:
        denied_row = con.execute(
            """
            SELECT validation_status, validation_method, evidence, notes
            FROM cloud_validation_results
            WHERE engagement_id=1001 AND asset_type='firebase' AND identifier='denied'
            """
        ).fetchone()
        assert denied_row == (
            "UNVERIFIED",
            "scope_manifest",
            "scope denied before cloud validation",
            "scope_manifest_denied",
        )
    finally:
        con.close()


def test_sweep_pending_cloud_asset_validations_denies_storage_assets_without_probe_or_findings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (?, ?, ?, ?)
            """,
            [
                (1001, "aws_s3", "denied-s3-assets", "artifact_extract"),
                (1001, "gcs", "denied-gcs-assets", "artifact_extract"),
                (1001, "azure_blob", "deniedblob/public", "artifact_extract"),
                (1001, "do_spaces", "nyc3/denied-space-assets", "artifact_extract"),
            ],
        )
        con.commit()
    finally:
        con.close()

    def _fail_validate_batch(*args, **kwargs):  # noqa: ANN002, ANN003
        del args, kwargs
        raise AssertionError("scope-denied storage assets must not reach provider validation")

    denied_callbacks: list[tuple[str, str, str]] = []
    monkeypatch.setattr(cloud_validate, "run_cloud_asset_validate_batch", _fail_validate_batch)

    summary = cloud_validate.sweep_pending_cloud_asset_validations(
        1001,
        db_path,
        limit=10,
        max_workers=4,
        scope_checker=lambda asset_type, identifier: False,
        scope_denied_callback=lambda asset_type, identifier, reason: denied_callbacks.append(
            (asset_type, identifier, reason)
        ),
    )

    assert denied_callbacks == [
        ("aws_s3", "denied-s3-assets", "scope_manifest_denied"),
        ("gcs", "denied-gcs-assets", "scope_manifest_denied"),
        ("azure_blob", "deniedblob/public", "scope_manifest_denied"),
        ("do_spaces", "nyc3/denied-space-assets", "scope_manifest_denied"),
    ]
    assert summary["status"] == "success"
    assert summary["attempted"] == 4
    assert summary["succeeded"] == 4
    assert summary["failed"] == 0
    assert summary["status_counts"] == {"UNVERIFIED": 4}
    assert [row["validation_status"] for row in summary["results"]] == [
        "UNVERIFIED",
        "UNVERIFIED",
        "UNVERIFIED",
        "UNVERIFIED",
    ]
    assert [row["validation_method"] for row in summary["results"]] == [
        "scope_manifest",
        "scope_manifest",
        "scope_manifest",
        "scope_manifest",
    ]

    con = sqlite3.connect(db_path)
    try:
        validation_rows = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method, evidence, notes
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY id
            """
        ).fetchall()
        assert validation_rows == [
            (
                "aws_s3",
                "denied-s3-assets",
                "UNVERIFIED",
                "scope_manifest",
                "scope denied before cloud validation",
                "scope_manifest_denied",
            ),
            (
                "gcs",
                "denied-gcs-assets",
                "UNVERIFIED",
                "scope_manifest",
                "scope denied before cloud validation",
                "scope_manifest_denied",
            ),
            (
                "azure_blob",
                "deniedblob/public",
                "UNVERIFIED",
                "scope_manifest",
                "scope denied before cloud validation",
                "scope_manifest_denied",
            ),
            (
                "do_spaces",
                "nyc3/denied-space-assets",
                "UNVERIFIED",
                "scope_manifest",
                "scope denied before cloud validation",
                "scope_manifest_denied",
            ),
        ]

        findings = con.execute(
            """
            SELECT vuln_type, severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY title
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_sweep_pending_cloud_asset_validations_parallelizes_scope_gate_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (?, ?, ?, ?)
            """,
            [
                (1001, "firebase", "allowed-one", "html_extract"),
                (1001, "supabase", "denied-one", "html_extract"),
                (1001, "aws_s3", "allowed-two", "html_extract"),
                (1001, "gcs", "denied-two", "html_extract"),
            ],
        )
        con.commit()
    finally:
        con.close()

    active_scope_checks = 0
    max_active_scope_checks = 0
    active_lock = threading.Lock()
    denied_callbacks: list[tuple[str, str, str]] = []
    validated_batches: list[list[tuple[str, str]]] = []

    def _scope_checker(asset_type: str, identifier: str) -> bool:
        nonlocal active_scope_checks, max_active_scope_checks
        del asset_type
        with active_lock:
            active_scope_checks += 1
            max_active_scope_checks = max(max_active_scope_checks, active_scope_checks)
        time.sleep(0.05)
        with active_lock:
            active_scope_checks -= 1
        return identifier.startswith("allowed")

    def _fake_validate_batch(engagement_id, assets, db_path, **kwargs):  # noqa: ANN001
        del engagement_id, db_path, kwargs
        normalized_assets = [(str(asset[0]), str(asset[1])) for asset in assets]
        validated_batches.append(normalized_assets)
        return {
            "status": "success",
            "engagement_id": 1001,
            "attempted": len(normalized_assets),
            "succeeded": len(normalized_assets),
            "failed": 0,
            "status_counts": {"VALIDATED": len(normalized_assets)},
            "results": [
                {
                    "status": "success",
                    "engagement_id": 1001,
                    "asset_type": asset_type,
                    "identifier": identifier,
                    "validation_status": "VALIDATED",
                    "validation_method": "stub",
                }
                for asset_type, identifier in normalized_assets
            ],
        }

    monkeypatch.setattr(cloud_validate, "run_cloud_asset_validate_batch", _fake_validate_batch)

    summary = cloud_validate.sweep_pending_cloud_asset_validations(
        1001,
        db_path,
        limit=10,
        max_workers=4,
        scope_checker=_scope_checker,
        scope_denied_callback=lambda asset_type, identifier, reason: denied_callbacks.append(
            (asset_type, identifier, reason)
        ),
    )

    assert max_active_scope_checks > 1
    assert validated_batches == [[("firebase", "allowed-one"), ("aws_s3", "allowed-two")]]
    assert denied_callbacks == [
        ("supabase", "denied-one", "scope_manifest_denied"),
        ("gcs", "denied-two", "scope_manifest_denied"),
    ]
    assert summary["attempted"] == 4
    assert summary["succeeded"] == 4
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 2
    assert summary["status_counts"]["UNVERIFIED"] == 2
    assert [row["identifier"] for row in summary["results"]] == [
        "denied-one",
        "denied-two",
        "allowed-one",
        "allowed-two",
    ]


def test_run_cloud_asset_validate_batch_scope_checker_skips_denied_assets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    def _fail_probe_cloud_asset_result(asset_type, identifier, **kwargs):  # noqa: ANN001
        del asset_type, identifier, kwargs
        raise AssertionError("scope-denied asset must not reach provider validation")

    denied_callbacks: list[tuple[str, str, str]] = []
    monkeypatch.setattr(cloud_validate, "_probe_cloud_asset_result", _fail_probe_cloud_asset_result)

    result = cloud_validate.run_cloud_asset_validate_batch(
        1001,
        [("firebase", "denied-project")],
        db_path,
        max_workers=2,
        scope_checker=lambda asset_type, identifier: False,
        scope_denied_callback=lambda asset_type, identifier, reason: denied_callbacks.append(
            (asset_type, identifier, reason)
        ),
    )

    assert denied_callbacks == [("firebase", "denied-project", "scope_manifest_denied")]
    assert result["attempted"] == 1
    assert result["succeeded"] == 1
    assert result["failed"] == 0
    assert result["status_counts"] == {"UNVERIFIED": 1}
    assert result["results"][0]["validation_status"] == "UNVERIFIED"
    assert result["results"][0]["validation_method"] == "scope_manifest"

    con = sqlite3.connect(db_path)
    try:
        denied_row = con.execute(
            """
            SELECT validation_status, validation_method, evidence, notes
            FROM cloud_validation_results
            WHERE engagement_id=1001 AND asset_type='firebase' AND identifier='denied-project'
            """
        ).fetchone()
        assert denied_row == (
            "UNVERIFIED",
            "scope_manifest",
            "scope denied before cloud validation",
            "scope_manifest_denied",
        )
    finally:
        con.close()


def test_sweep_pending_cloud_validations_emits_progress_metrics(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, validation_state)
            VALUES
                (?, 1001, ?, ?, ?, 'crawler', ?, 'webapp', ?, 'UNCONFIRMED')
            """,
            [
                (
                    21,
                    "acme-firebase-prod",
                    "firebase",
                    "firebase_web_config",
                    "https://acme-firebase-prod.firebaseapp.com/__/firebase/init.json",
                    "AIza...7890",
                ),
                (
                    22,
                    "https://acme-workspace.supabase.co",
                    "supabase",
                    "supabase_mobile_config",
                    "https://acme-workspace.supabase.co/rest/v1/",
                    "sb_publishable_1234",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(cloud_validate.httpx, "Client", _MixedBatchClient)
    progress_events: list[tuple[str, dict[str, object]]] = []
    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=4,
        progress_label="1.K6 cloud key validation",
        progress_callback=lambda label, metrics: progress_events.append((label, dict(metrics))),
    )

    assert summary["status"] == "success"
    assert progress_events
    assert progress_events[0][0] == "1.K6 cloud key validation"
    assert int(progress_events[0][1]["completed"]) == 0
    assert int(progress_events[-1][1]["completed"]) == 2
    assert int(progress_events[-1][1]["total"]) == 2
    assert int(progress_events[-1][1]["queue_depth"]) == 0
    assert float(progress_events[-1][1]["eta_seconds"] or 0.0) == 0.0


def test_sweep_pending_cloud_validations_claims_rows_before_provider_call(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, validation_state)
            VALUES
                (31, 1001, 'acme-firebase-prod', 'firebase', 'firebase_web_config', 'crawler',
                 'https://acme-firebase-prod.firebaseapp.com/__/firebase/init.json',
                 'webapp', 'AIza...7890', 'UNCONFIRMED')
            """
        )
        con.commit()
    finally:
        con.close()

    nested_summaries: list[dict[str, object]] = []
    provider_calls: list[int] = []

    def _fake_validate_key_row_payload(row_payload, **kwargs):  # noqa: ANN001, ANN003
        del kwargs
        provider_calls.append(int(row_payload["id"]))
        if len(provider_calls) == 1:
            nested_summaries.append(
                cloud_validate.sweep_pending_cloud_validations(
                    1001,
                    db_path,
                    limit=10,
                    max_workers=1,
                )
            )
        return (
            int(row_payload["id"]),
            int(row_payload["engagement_id"]),
            cloud_validate.CloudValidationResult(
                asset_type="firebase",
                identifier="acme-firebase-prod",
                validation_status="ACCESSIBLE_BUT_NO_DATA",
                validation_method="stub_provider",
                evidence="stub",
                notes="stubbed provider response",
            ),
        )

    monkeypatch.setattr(cloud_validate, "_validate_key_row_payload", _fake_validate_key_row_payload)

    summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=10,
        max_workers=1,
    )

    assert [item["attempted"] for item in nested_summaries] == [0]
    assert provider_calls == [31]
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1

    con = sqlite3.connect(db_path)
    try:
        assert con.execute("SELECT COUNT(*) FROM validation_claims").fetchone()[0] == 0
    finally:
        con.close()


def test_sweep_pending_cloud_validations_persists_provider_exception_receipts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend,
                 source_url, repo_name, key_redacted, validation_state)
            VALUES
                (?, 1001, ?, ?, ?, 'crawler', ?, 'webapp', ?, 'UNCONFIRMED')
            """,
            [
                (
                    41,
                    "acme-firebase-prod",
                    "firebase",
                    "firebase_web_config",
                    "https://acme-firebase-prod.firebaseapp.com/__/firebase/init.json",
                    "AIza...7890",
                ),
                (
                    42,
                    "https://acme-workspace.supabase.co",
                    "supabase",
                    "supabase_mobile_config",
                    "https://acme-workspace.supabase.co/rest/v1/",
                    "sb_publishable_1234",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    provider_calls: list[int] = []

    def _fake_validate_key_row_payload(row_payload, **kwargs):  # noqa: ANN001, ANN003
        del kwargs
        provider_calls.append(int(row_payload["id"]))
        raise RuntimeError("raw secret should not leak")

    monkeypatch.setattr(cloud_validate, "_validate_key_row_payload", _fake_validate_key_row_payload)

    first_summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=2,
        max_workers=2,
        only_unattempted=True,
    )
    second_summary = cloud_validate.sweep_pending_cloud_validations(
        1001,
        db_path,
        limit=2,
        max_workers=2,
        only_unattempted=True,
    )

    assert first_summary["attempted"] == 2
    assert first_summary["succeeded"] == 0
    assert first_summary["failed"] == 2
    assert first_summary["status_counts"] == {"UNVERIFIED": 2}
    assert second_summary["attempted"] == 0
    assert provider_calls == [41, 42]
    assert "raw secret" not in json.dumps(first_summary)

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT asset_type, identifier, validation_status, validation_method, evidence, notes
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        key_rows = con.execute(
            """
            SELECT id, validation_state, validation_detail, validated_at
            FROM key_scanner_findings
            WHERE id IN (41, 42)
            ORDER BY id
            """
        ).fetchall()
        claim_count = con.execute("SELECT COUNT(*) FROM validation_claims").fetchone()[0]
    finally:
        con.close()

    assert rows == [
        (
            "firebase",
            "https://acme-firebase-prod.firebaseapp.com/__/firebase/init.json",
            "UNVERIFIED",
            "provider_exception",
            "provider exception converted to non-reportable key validation receipt",
            "provider_exception:RuntimeError",
        ),
        (
            "supabase",
            "https://acme-workspace.supabase.co/rest/v1/",
            "UNVERIFIED",
            "provider_exception",
            "provider exception converted to non-reportable key validation receipt",
            "provider_exception:RuntimeError",
        ),
    ]
    assert [row[0] for row in key_rows] == [41, 42]
    assert all(row[1] == "UNCONFIRMED" for row in key_rows)
    assert all(str(row[2]).startswith("UNVERIFIED:provider_exception:") for row in key_rows)
    assert all(row[3] for row in key_rows)
    assert claim_count == 0


def test_sweep_pending_cloud_asset_validations_claims_assets_before_provider_batch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (1001, 'aws_s3', 'acme-public-assets', 'artifact_s3_uri')
            """
        )
        con.commit()
    finally:
        con.close()

    nested_summaries: list[dict[str, object]] = []
    provider_batches: list[list[tuple[str, str]]] = []

    def _fake_validate_batch(engagement_id, assets, batch_db_path, **kwargs):  # noqa: ANN001
        del batch_db_path, kwargs
        normalized_assets = [(str(asset[0]), str(asset[1])) for asset in assets]
        provider_batches.append(normalized_assets)
        nested_summaries.append(
            cloud_validate.sweep_pending_cloud_asset_validations(
                int(engagement_id),
                db_path,
                limit=10,
                max_workers=1,
            )
        )
        return {
            "status": "success",
            "engagement_id": int(engagement_id),
            "attempted": len(normalized_assets),
            "succeeded": len(normalized_assets),
            "failed": 0,
            "status_counts": {"VALIDATED": len(normalized_assets)},
            "results": [
                {
                    "status": "success",
                    "engagement_id": int(engagement_id),
                    "asset_type": asset_type,
                    "identifier": identifier,
                    "provider_identifier": identifier,
                    "validation_status": "VALIDATED",
                    "validation_method": "stub_provider",
                }
                for asset_type, identifier in normalized_assets
            ],
        }

    monkeypatch.setattr(cloud_validate, "run_cloud_asset_validate_batch", _fake_validate_batch)

    summary = cloud_validate.sweep_pending_cloud_asset_validations(
        1001,
        db_path,
        limit=10,
        max_workers=1,
    )

    assert [item["attempted"] for item in nested_summaries] == [0]
    assert provider_batches == [[("aws_s3", "acme-public-assets")]]
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1

    con = sqlite3.connect(db_path)
    try:
        assert con.execute("SELECT COUNT(*) FROM validation_claims").fetchone()[0] == 0
    finally:
        con.close()


def test_sweep_pending_cloud_asset_validations_processes_unvalidated_digitalocean_spaces_assets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (1001, 'do_spaces', 'nyc3/acme-space-public', 'artifact_url_extract')
            """
        )
        con.commit()
    finally:
        con.close()

    monkeypatch.setattr(cloud_validate.httpx, "Client", _DOSpacesClient)
    summary = cloud_validate.sweep_pending_cloud_asset_validations(
        1001,
        db_path,
        limit=10,
        max_workers=4,
    )

    assert summary["status"] == "success"
    assert summary["attempted"] == 1
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["status_counts"]["VALIDATED"] == 1
    assert summary["results"][0]["identifier"] == "nyc3/acme-space-public"
    assert summary["results"][0]["asset_type"] == "do_spaces"

    con = sqlite3.connect(db_path)
    try:
        validation_row = con.execute(
            """
            SELECT asset_type, identifier, validation_status
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert validation_row == ("do_spaces", "nyc3/acme-space-public", "VALIDATED")
    finally:
        con.close()
