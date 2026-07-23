from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forge.engagement_orchestrator import ArtifactDownloadResult, ArtifactQueueProcessor

OPENID_URL = "https://login.acme.test/.well-known/openid-configuration"
JWKS_URL = "https://login.acme.test/.well-known/jwks.json"


def write_local_artifact_fixtures(tmp_path: Path, *, supabase_jwt: str) -> None:
    config = tmp_path / "data" / "artifacts" / "client-config.js"
    config.parent.mkdir(parents=True)
    config.write_text(
        f"""
        export const FIREBASE_URL = "https://artifact-firebase-prod.firebaseio.com";
        export const FIREBASE_DUP = "https://artifact-firebase-prod.firebaseio.com";
        export const DEAD_FIREBASE = "https://dead-firebase-prod.firebaseio.com";
        export const SUPABASE_URL = "https://acmebase.supabase.co";
        export const SUPABASE_ANON_KEY = "{supabase_jwt}";
        export const OWNER = "artifact-owner@acme.test";
        export const DUPLICATE_OWNER = "ops@acme.test";
        export const CONFIG_URL = "https://app.acme.test/config";
        """.strip(),
        encoding="utf-8",
    )
    _write_opensearch(config.parent / "opensearch.xml")
    _write_saml_metadata(config.parent / "saml-metadata.xml")
    _write_web_manifest(config.parent / "site.webmanifest")
    _write_mobile_association_metadata(config.parent / ".well-known")
    _write_security_txt(config.parent / ".well-known" / "security.txt")
    _write_feed(config.parent / "feed.xml")
    _write_json_feed(config.parent / "feed.json")


def install_remote_metadata_download_mock(monkeypatch: Any, tmp_path: Path) -> None:
    openid_body = json.dumps(
        {
            "issuer": "https://login.acme.test",
            "authorization_endpoint": "/oauth2/v1/authorize",
            "token_endpoint": "https://login-api.acme.test/oauth2/v1/token",
            "userinfo_endpoint": "./userinfo",
            "jwks_uri": JWKS_URL,
            "service_documentation": "https://docs.acme.test/oauth#ignored",
            "contacts": ["oauth-owner@acme.test"],
            "templated_endpoint": "/oauth/{tenant}/authorize",
            "supabase": {
                "type": "supabase",
                "projectRef": "openidvault",
                "url": "https://openidvault.supabase.co",
            },
        },
        sort_keys=True,
    )
    jwks_body = json.dumps(
        {
            "owner": "jwks-owner@acme.test",
            "keys": [
                {"kid": "signing-key", "kty": "RSA", "x5u": "../certs/signing.pem"},
                {
                    "kid": "delegated-key-set",
                    "kty": "EC",
                    "jku": "https://keys.acme.test/.well-known/tenant-jwks.json#ignored",
                },
                {"kid": "templated-noise", "x5u": "/certs/{tenant}/key.pem"},
            ],
        },
        sort_keys=True,
    )

    def remote_artifact_download(self: ArtifactQueueProcessor, request: Any) -> ArtifactDownloadResult:
        del self
        if request.source_url == OPENID_URL:
            return _download_result(
                tmp_path,
                request,
                filename="openid-configuration",
                body=openid_body,
                content_type="application/json",
            )
        if request.source_url == JWKS_URL:
            return _download_result(
                tmp_path,
                request,
                filename="jwks.json",
                body=jwks_body,
                content_type="application/jwk-set+json",
            )
        return ArtifactDownloadResult(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=request.artifact_type,
            error="mock remote artifact unavailable",
        )

    monkeypatch.setattr(ArtifactQueueProcessor, "_download_remote_artifact_request", remote_artifact_download)


def _download_result(
    tmp_path: Path,
    request: Any,
    *,
    filename: str,
    body: str,
    content_type: str,
) -> ArtifactDownloadResult:
    download_path = tmp_path / "downloads" / filename
    download_path.parent.mkdir(parents=True, exist_ok=True)
    download_path.write_text(body, encoding="utf-8")
    return ArtifactDownloadResult(
        artifact_id=request.artifact_id,
        source_url=request.source_url,
        artifact_type=request.artifact_type,
        path=download_path,
        metadata_extra={
            "content_type": content_type,
            "downloaded_from_remote": True,
            "download_filename": filename,
        },
    )


def _write_opensearch(path: Path) -> None:
    path.write_text(
        """
        <OpenSearchDescription
            xmlns="http://a9.com/-/spec/opensearch/1.1/"
            xmlns:moz="http://www.mozilla.org/2006/browser/search/">
          <Url type="text/html"
               template="https://search.acme.test/query?q={searchTerms}&amp;token=hidden&amp;view=public" />
          <moz:SearchForm>https://search.acme.test/advanced</moz:SearchForm>
          <Developer>search-owner@acme.test</Developer>
        </OpenSearchDescription>
        """.strip(),
        encoding="utf-8",
    )


def _write_saml_metadata(path: Path) -> None:
    path.write_text(
        """
        <md:EntityDescriptor
            xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
            entityID="https://idp.acme.test/saml/metadata?tenant=hidden">
          <md:IDPSSODescriptor>
            <md:SingleSignOnService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                Location="https://login.acme.test/sso/login?SAMLRequest=secret&amp;client=acme" />
            <md:SingleLogoutService
                Location="//logout.acme.test/saml/logout#ignored" />
            <md:ArtifactResolutionService
                Location="https://artifact.acme.test/saml/artifact?token=secret" />
          </md:IDPSSODescriptor>
          <md:Organization>
            <md:OrganizationURL xml:lang="en">
              https://www.acme.test/security/sso?api_key=hidden
            </md:OrganizationURL>
          </md:Organization>
          <md:ContactPerson>
            <md:EmailAddress>sso-owner@acme.test</md:EmailAddress>
          </md:ContactPerson>
          <md:AdditionalMetadataLocation Location="/tenant/{id}/metadata.xml" />
        </md:EntityDescriptor>
        """.strip(),
        encoding="utf-8",
    )


def _write_feed(path: Path) -> None:
    path.write_text(
        """
        <rss version="2.0"
             xmlns:atom="http://www.w3.org/2005/Atom"
             xmlns:media="http://search.yahoo.com/mrss/">
          <channel>
            <title>Acme Updates</title>
            <link>https://news.acme.test/blog?token=hidden</link>
            <atom:link rel="self" href="https://news.acme.test/feed.xml?signature=hidden" />
            <item>
              <link>https://news.acme.test/posts/launch?api_key=hidden&amp;view=public</link>
              <media:content url="https://media.acme.test/demo.mp4#ignored" />
            </item>
            <managingEditor>feed-owner@acme.test</managingEditor>
          </channel>
        </rss>
        """.strip(),
        encoding="utf-8",
    )


def _write_web_manifest(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "name": "Acme Portal",
                "start_url": "https://manifest.acme.test/app?token=hidden",
                "scope": "https://manifest.acme.test/app/",
                "shortcuts": [{"url": "https://manifest.acme.test/billing"}],
                "share_target": {"action": "https://manifest.acme.test/share?sig=hidden"},
                "icons": [{"src": "https://manifest.acme.test/icons/app.png#ignored"}],
                "description": "Contact manifest-owner@acme.test",
                "templated": "https://manifest.acme.test/tenant/{id}/launch",
                "supabase": "https://manifestvault.supabase.co",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_mobile_association_metadata(well_known_dir: Path) -> None:
    well_known_dir.mkdir(parents=True, exist_ok=True)
    (well_known_dir / "assetlinks.json").write_text(
        json.dumps(
            [
                {
                    "relation": ["delegate_permission/common.handle_all_urls"],
                    "target": {
                        "namespace": "android_app",
                        "package_name": "com.acme.portal",
                        "sha256_cert_fingerprints": ["AA:BB:CC"],
                    },
                },
                {"target": {"namespace": "android_app", "package_name": "not a package"}},
                {
                    "target": {
                        "namespace": "web",
                        "site": "https://assetlinks.acme.test/android?token=hidden",
                    },
                },
                {
                    "contact": "assetlinks-owner@acme.test",
                    "supabase": "https://assetlinksvault.supabase.co",
                },
            ],
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "apple-app-site-association").write_text(
        json.dumps(
            {
                "applinks": {
                    "details": [
                        {
                            "appIDs": [
                                "ABCDE12345.com.acme.portal",
                                "ABCDE12345.*",
                                "not-an-app-id",
                            ],
                            "components": [
                                {
                                    "/": "/support/*",
                                    "comment": (
                                        "Contact aasa-owner@acme.test via "
                                        "https://aasa-docs.acme.test/help?token=hidden"
                                    ),
                                }
                            ],
                        }
                    ]
                },
                "webcredentials": {
                    "apps": ["ABCDE12345.com.acme.credentials"],
                    "supabase": "https://aasavault.supabase.co",
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_security_txt(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
        Contact: mailto:securitytxt-owner@acme.test
        Contact: https://security.acme.test/report?token=hidden
        Policy: https://security.acme.test/policy?api_key=hidden
        Hiring: https://jobs.acme.test/security?signature=hidden
        Supabase: https://securitytxtvault.supabase.co
        Firebase: https://securitytxt-firebase.firebaseio.com
        """.strip(),
        encoding="utf-8",
    )


def _write_json_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "version": "https://jsonfeed.org/version/1.1",
                "title": "Acme JSON Updates",
                "home_page_url": "https://jsonfeed.acme.test/blog?token=hidden",
                "feed_url": "https://jsonfeed.acme.test/feed.json?signature=hidden",
                "author": {
                    "email": "json-feed-owner@acme.test",
                    "url": "https://people.acme.test/json-feed-owner?api_key=hidden",
                },
                "items": [
                    {
                        "id": "json-launch",
                        "url": "https://jsonfeed.acme.test/posts/launch?sig=hidden&view=public",
                        "external_url": "https://cdn-json.acme.test/downloads/app.apk?signature=hidden",
                        "attachments": [{"url": "https://media-json.acme.test/podcast.mp3#ignored"}],
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
