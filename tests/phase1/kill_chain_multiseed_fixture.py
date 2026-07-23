from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forge.engagement_orchestrator import ArtifactDownloadResult, ArtifactQueueProcessor
from forge.reporting.dashboard import generate_dashboard

OPENID_URL = "https://login.acme.test/.well-known/openid-configuration"
JWKS_URL = "https://login.acme.test/.well-known/jwks.json"
VALIDATED_PUBLIC_METADATA_IDENTIFIERS = (
    "csafe2evault",
    "sbom-e2e-firebase",
    "passkeye2evault",
    "sshknowne2evault",
    "pki-e2e-firebase",
    "gpce2evault",
    "tdm-e2e-firebase",
    "pubvendorse2evault",
    "truste2evault",
    "dnt-e2e-firebase",
    "privacysandboxe2evault",
    "agentcarde2evault",
    "api-catalog-e2e-firebase",
    "orde2evault",
    "mercuree2evault",
    "webweaver-e2e-firebase",
    "didconfige2evault",
    "keybasee2evault",
    "smartconfig-e2e-firebase",
    "terraformconfige2evault",
)


def assert_dashboard_review_visibility(
    *,
    data_dir: Path,
    reports_dir: Path,
    engagement_id: int,
    fallback_reason: str,
) -> None:
    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    site_root = reports_dir / "dashboard"
    overview = json.loads((site_root / "data" / "engagements.json").read_text(encoding="utf-8"))
    item = next(row for row in overview["items"] if row["id"] == str(engagement_id))
    slug = item["slug"]
    assert slug.startswith(f"engagement-{engagement_id}-")
    assert slug.endswith("acme-test")
    assert item["detail_route"] == f"engagements/{slug}/"
    assert item["run_summary"]["status"] == "completed"

    detail_page = site_root / "engagements" / slug / "index.html"
    detail_json = site_root / "data" / "engagements" / f"{slug}.json"
    assert detail_page.exists()
    assert detail_json.exists()
    detail_html = detail_page.read_text(encoding="utf-8")
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    report_summary = detail_payload["report_summary"]
    assert report_summary["provider"] == "template"
    assert report_summary["requested_provider"] == "auto"
    assert report_summary["render_backend"] == "template"
    assert report_summary["fallback_reason"] == fallback_reason
    assert str(report_summary["findings_checksum"]).startswith("sha256:")
    assert {item["label"] for item in report_summary["available_exports"]} == {
        "Markdown",
        "PDF",
        "Report JSON",
        "CSV",
    }

    run_summary = detail_payload["run_summary"]
    assert run_summary["status"] == "completed"
    assert int(run_summary["current_iteration"]) < 4
    assert (run_summary["metadata"] or {}).get("last_iteration_stable") is True
    assert "artifact-owner@acme.test" in detail_payload["seeds"]

    findings = detail_payload["sections"]["vulnerability_findings"]
    assert {row["Title"] for row in findings} >= {
        "Validated Firebase data exposure",
        "Validated Supabase data exposure",
    }
    assert not any("dead-firebase-prod" in json.dumps(row, sort_keys=True) for row in findings)

    validation_rows = {
        (row["Type"], row["Asset"]): row
        for row in detail_payload["sections"]["cloud_validation_results"]
    }
    assert validation_rows[("firebase", "dead-firebase-prod")]["Status"] == "UNVERIFIED"
    assert validation_rows[("supabase", "acmebase")]["Status"] == "VALIDATED"

    graph_payload = detail_payload["graph_payload"]
    vuln_nodes = [
        node
        for node in graph_payload["nodes"]
        if node.get("source_table") == "vulnerability_findings"
    ]
    assert vuln_nodes
    assert all((node.get("metadata") or {}).get("validation_status") == "VALIDATED" for node in vuln_nodes)
    assert not any("dead-firebase-prod" in json.dumps(node, sort_keys=True) for node in vuln_nodes)
    assert "Maltego Workspace" in detail_html
    assert f"Fallback reason: {fallback_reason}" in detail_html


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
    _write_public_ai_metadata(config.parent)
    _write_well_known_supply_chain_metadata(config.parent / ".well-known")
    _write_well_known_privacy_vendor_metadata(config.parent / ".well-known")
    _write_well_known_api_application_metadata(config.parent / ".well-known")
    _write_well_known_service_metadata(config.parent / ".well-known")
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


def _write_public_ai_metadata(artifact_dir: Path) -> None:
    (artifact_dir / "llms.txt").write_text(
        """
        Contact: mailto:llms-e2e-owner@acme.test
        Docs: https://llms.acme.test/context?token=hidden
        OpenAPI: https://llms.acme.test/openapi.yaml?api_key=hidden
        Supabase: https://llmse2evault.supabase.co
        Template: https://llms.acme.test/{tenant}/agent
        """.strip(),
        encoding="utf-8",
    )
    (artifact_dir / "ai.txt").write_text(
        """
        contact: ai-e2e-owner@acme.test
        Policy: https://ai.acme.test/policy?signature=hidden
        Docs: https://ai.acme.test/docs?token=hidden
        Firebase: https://ai-e2e-firebase.firebaseio.com
        Template: https://ai.acme.test/{workspace}/agent
        """.strip(),
        encoding="utf-8",
    )
    (artifact_dir / "ai-plugin.json").write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "name_for_human": "Acme Plugin",
                "name_for_model": "acme_plugin",
                "contact_email": "aiplugin-e2e-owner@acme.test",
                "api": {
                    "type": "openapi",
                    "url": "https://plugin.acme.test/openapi.yaml?token=hidden",
                },
                "auth": {
                    "authorization_url": "https://plugin.acme.test/oauth/authorize?api_key=hidden",
                },
                "description_for_model": (
                    "Firebase https://aiplugin-e2e-firebase.firebaseio.com and "
                    "docs https://plugin.acme.test/docs?signature=hidden"
                ),
                "legal_info_url": "https://plugin.acme.test/legal?signature=hidden",
                "templated_endpoint": "https://plugin.acme.test/{tenant}/openapi.yaml",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_well_known_supply_chain_metadata(well_known_dir: Path) -> None:
    well_known_dir.mkdir(parents=True, exist_ok=True)
    (well_known_dir / "csaf").write_text(
        json.dumps(
            {
                "provider_metadata": {
                    "url": "https://supply.acme.test/csaf/provider.json?token=hidden",
                    "contact": "csaf-e2e-owner@acme.test",
                },
                "supabase": "https://csafe2evault.supabase.co",
                "template": "https://supply.acme.test/csaf/{tenant}/provider.json",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "sbom").write_text(
        json.dumps(
            {
                "spdx": "https://sbom.acme.test/spdx/app.spdx.json?api_key=hidden",
                "contact": "sbom-e2e-owner@acme.test",
                "firebase": "https://sbom-e2e-firebase.firebaseio.com",
                "template": "https://sbom.acme.test/{build}/app.spdx.json",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "passkey-endpoints").write_text(
        json.dumps(
            {
                "enroll": "https://login.acme.test/passkeys/enroll?signature=hidden",
                "manage": "https://login.acme.test/passkeys/manage?token=hidden",
                "support": "passkey-e2e-owner@acme.test",
                "supabase": "https://passkeye2evault.supabase.co",
                "templated_endpoint": "https://login.acme.test/passkeys/{tenant}/manage",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "ssh-known-hosts").write_text(
        """
        ssh-supply.acme.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample
        Contact: sshknown-e2e-owner@acme.test
        Docs: https://ssh.acme.test/known-hosts?api_key=hidden
        Supabase: https://sshknowne2evault.supabase.co
        """.strip(),
        encoding="utf-8",
    )
    (well_known_dir / "pki-validation").write_text(
        """
        CA validation placeholder for static review only.
        Contact: pki-e2e-owner@acme.test
        Docs: https://pki.acme.test/validation?token=hidden
        Firebase: https://pki-e2e-firebase.firebaseio.com
        Template: https://pki.acme.test/{tenant}/validation
        """.strip(),
        encoding="utf-8",
    )


def _write_well_known_privacy_vendor_metadata(well_known_dir: Path) -> None:
    well_known_dir.mkdir(parents=True, exist_ok=True)
    (well_known_dir / "gpc.json").write_text(
        json.dumps(
            {
                "gpc": True,
                "policy": "https://privacy.acme.test/gpc?token=hidden",
                "contact": "gpc-e2e-owner@acme.test",
                "supabase": "https://gpce2evault.supabase.co",
                "template": "https://privacy.acme.test/{tenant}/gpc",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "tdmrep.json").write_text(
        json.dumps(
            {
                "tdm-reservation": 1,
                "policy": "https://privacy.acme.test/tdm?api_key=hidden",
                "contact": "tdm-e2e-owner@acme.test",
                "firebase": "https://tdm-e2e-firebase.firebaseio.com",
                "template": "https://privacy.acme.test/{workspace}/tdm",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "pubvendors.json").write_text(
        json.dumps(
            {
                "publisher": "Acme",
                "vendors": [{"policyUrl": "https://vendors.acme.test/policy?signature=hidden"}],
                "contact": "pubvendors-e2e-owner@acme.test",
                "supabase": "https://pubvendorse2evault.supabase.co",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "trust.txt").write_text(
        """
        Contact: trust-e2e-owner@acme.test
        Policy: https://trust.acme.test/policy?token=hidden
        Transparency: https://trust.acme.test/transparency?signature=hidden
        Supabase: https://truste2evault.supabase.co
        Template: https://trust.acme.test/{tenant}/policy
        """.strip(),
        encoding="utf-8",
    )
    (well_known_dir / "dnt-policy.txt").write_text(
        """
        Contact: dnt-e2e-owner@acme.test
        Policy: https://privacy.acme.test/dnt?api_key=hidden
        Firebase: https://dnt-e2e-firebase.firebaseio.com
        Template: https://privacy.acme.test/{tenant}/dnt
        """.strip(),
        encoding="utf-8",
    )
    (well_known_dir / "privacy-sandbox-attestations.json").write_text(
        json.dumps(
            {
                "attestations": ["https://privacy.acme.test/sandbox/attestation?token=hidden"],
                "contact": "privacysandbox-e2e-owner@acme.test",
                "supabase": "https://privacysandboxe2evault.supabase.co",
                "template": "https://privacy.acme.test/{tenant}/sandbox/attestation",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_well_known_api_application_metadata(well_known_dir: Path) -> None:
    well_known_dir.mkdir(parents=True, exist_ok=True)
    (well_known_dir / "agent-card.json").write_text(
        json.dumps(
            {
                "name": "Acme Agent",
                "url": "https://agent.acme.test/a2a?token=hidden",
                "documentationUrl": "https://agent.acme.test/docs?api_key=hidden",
                "contact": "agentcard-e2e-owner@acme.test",
                "supabase": "https://agentcarde2evault.supabase.co",
                "template": "https://agent.acme.test/{tenant}/a2a",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "api-catalog").write_text(
        json.dumps(
            {
                "apis": [{"name": "public", "url": "https://api-catalog.acme.test/catalog?signature=hidden"}],
                "support": "apicatalog-e2e-owner@acme.test",
                "firebase": "https://api-catalog-e2e-firebase.firebaseio.com",
                "template": "https://api-catalog.acme.test/{workspace}/catalog",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "open-resource-discovery").write_text(
        json.dumps(
            {
                "resources": ["https://resources.acme.test/.well-known/open-resource-discovery?token=hidden"],
                "contact": "ord-e2e-owner@acme.test",
                "supabase": "https://orde2evault.supabase.co",
                "template": "https://resources.acme.test/{tenant}/open-resource-discovery",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "mercure").write_text(
        """
        hub=https://mercure.acme.test/.well-known/mercure?api_key=hidden
        subscribe=https://mercure.acme.test/subscribe?token=hidden
        publish=https://mercure.acme.test/publish?signature=hidden
        contact=mercure-e2e-owner@acme.test
        supabase=https://mercuree2evault.supabase.co
        template=https://mercure.acme.test/{tenant}/hub
        """.strip(),
        encoding="utf-8",
    )
    (well_known_dir / "webweaver.json").write_text(
        json.dumps(
            {
                "endpoint": "https://webweaver.acme.test/api?token=hidden",
                "documentationUrl": "https://webweaver.acme.test/docs?api_key=hidden",
                "support": "webweaver-e2e-owner@acme.test",
                "firebase": "https://webweaver-e2e-firebase.firebaseio.com",
                "template": "https://webweaver.acme.test/{tenant}/api",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_well_known_service_metadata(well_known_dir: Path) -> None:
    well_known_dir.mkdir(parents=True, exist_ok=True)
    (well_known_dir / "did-configuration.json").write_text(
        json.dumps(
            {
                "linked_dids": [
                    "did:web:didservice.acme.test",
                    "https://identity-service.acme.test/.well-known/did.json?token=hidden",
                ],
                "contact": "didconfig-e2e-owner@acme.test",
                "supabase": "https://didconfige2evault.supabase.co",
                "template": "https://identity-service.acme.test/{tenant}/did.json",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "keybase.txt").write_text(
        """
        keybase proof for acme service metadata
        contact=keybase-e2e-owner@acme.test
        profile=https://keybase.io/acmeserviceproof?api_key=hidden
        supabase=https://keybasee2evault.supabase.co
        template=https://keybase.io/{tenant}
        """.strip(),
        encoding="utf-8",
    )
    (well_known_dir / "smart-configuration").write_text(
        json.dumps(
            {
                "authorization_endpoint": "https://ehr.acme.test/oauth/authorize?token=hidden",
                "token_endpoint": "https://ehr.acme.test/oauth/token?api_key=hidden",
                "management_endpoint": "https://ehr.acme.test/smart/manage?signature=hidden",
                "support": "smartconfig-e2e-owner@acme.test",
                "firebase": "https://smartconfig-e2e-firebase.firebaseio.com",
                "template": "https://ehr.acme.test/{tenant}/smart/manage",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (well_known_dir / "terraform.json").write_text(
        json.dumps(
            {
                "modules.v1": "https://terraform.acme.test/v1/modules/?token=hidden",
                "login.v1": "https://terraform.acme.test/v1/login/?api_key=hidden",
                "support": "terraform-e2e-owner@acme.test",
                "supabase": "https://terraformconfige2evault.supabase.co",
                "template": "https://terraform.acme.test/{workspace}/v1/modules",
            },
            sort_keys=True,
        ),
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
