from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent
from typing import Callable

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_queue_processor_extracts_api_spec_and_client_collection_artifacts(
    tmp_path: Path,
    bootstrap_engagement: Callable[[Path], None],
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_api_specs"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    openapi_path = artifact_root / "openapi"
    openapi_path.write_text(
        """
        openapi: 3.1.0
        info:
          title: Acme API
          contact:
            email: openapi-owner@acme.example
        servers:
          - url: https://openapi.acme.example/v1
          - url: openapi-hostonly.acme.example/v2
        externalDocs:
          url: docs.openapi.acme.example/reference
        x-firebase: https://openapi-firebase.firebaseio.com
        x-supabase-url: https://openapiworkspace.supabase.co
        x-supabase-key: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9wZW5hcGl3b3Jrc3BhY2UiLCJyb2xlIjoiYW5vbiJ9.signature999
        x-bucket: s3://acme-openapi-bucket/specs/latest.json
        """.strip(),
        encoding="utf-8",
    )
    swagger_path = artifact_root / "swagger.yaml"
    swagger_path.write_text(
        dedent(
            """
            swagger: "2.0"
            info:
              title: Acme Legacy API
            schemes:
              - https
            host: swagger-host.acme.example
            basePath: /api/v2
            """
        ).strip(),
        encoding="utf-8",
    )
    api_blueprint_path = artifact_root / "apiary.apib"
    api_blueprint_path.write_text(
        dedent(
            """
            FORMAT: 1A
            HOST: apib-hostonly.acme.example/api

            # Acme API Blueprint

            Contact: apib-owner@acme.example

            # Group Users

            ## Users Collection [/users]
            """
        ).strip(),
        encoding="utf-8",
    )
    arazzo_path = artifact_root / "workflow.arazzo"
    arazzo_path.write_text(
        dedent(
            """
            arazzo: 1.0.1
            info:
              title: Acme API workflows
              version: 1.0.0
              contact:
                email: arazzo-owner@acme.example
            sourceDescriptions:
              - name: public
                type: openapi
                url: arazzo-source.acme.example/openapi.yaml
              - name: templated
                type: openapi
                url: https://${tenant}.acme.example/openapi.yaml
            workflows:
              - workflowId: login
                steps:
                  - stepId: create-session
                    operationId: createSession
            """
        ).strip(),
        encoding="utf-8",
    )
    overlay_path = artifact_root / "petstore.openapi-overlay"
    overlay_path.write_text(
        dedent(
            """
            overlay: 1.0.0
            info:
              title: Acme OpenAPI overlay
              version: 1.0.0
              contact:
                email: overlay-owner@acme.example
            extends: https://overlay-source.acme.example/openapi.yaml
            actions:
              - target: $.servers
                update:
                  - url: overlay-hostonly.acme.example/api
              - target: $.x-tenant
                update:
                  url: https://${tenant}.acme.example/template
            """
        ).strip(),
        encoding="utf-8",
    )
    postman_env_path = artifact_root / "acme.postman_environment.json"
    postman_env_path.write_text(
        json.dumps(
            {
                "name": "Acme Environment",
                "values": [
                    {"key": "baseUrl", "value": "postman-env-file.acme.example/api"},
                    {"key": "tenantName", "value": "ignored"},
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    hoppscotch_path = artifact_root / "hoppscotch_collection.json"
    hoppscotch_path.write_text(
        json.dumps(
            {
                "v": 1,
                "requests": [
                    {"endpoint": "hoppscotch-hostonly.acme.example/api"},
                ],
                "variables": [
                    {"key": "baseUrl", "value": "hoppscotch-env.acme.example/api"},
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    thunder_path = artifact_root / "thunder-collection.json"
    thunder_path.write_text(
        json.dumps(
            {
                "client": "Thunder Client",
                "requests": [
                    {"url": "thunder-hostonly.acme.example/api"},
                ],
                "environment": [
                    {"name": "baseUrl", "value": "thunder-env.acme.example/api"},
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    soapui_path = artifact_root / "soapui-project.xml"
    soapui_path.write_text(
        dedent(
            """
            <con:soapui-project xmlns:con="http://eviware.com/soapui/config">
              <con:properties>
                <con:property>
                  <con:name>owner</con:name>
                  <con:value>soapui-owner@acme.example</con:value>
                </con:property>
              </con:properties>
              <con:interface name="Acme">
                <con:endpoints>
                  <con:endpoint>soapui-hostonly.acme.example/service</con:endpoint>
                  <con:endpoint>https://soapui-live.acme.example/api</con:endpoint>
                  <con:endpoint>https://{tenant}.acme.example/api</con:endpoint>
                </con:endpoints>
                <con:request endpoint="soapui-attr.acme.example/rpc" />
              </con:interface>
            </con:soapui-project>
            """
        ).strip(),
        encoding="utf-8",
    )
    jmeter_path = artifact_root / "load-test.jmx"
    jmeter_path.write_text(
        dedent(
            """
            <jmeterTestPlan version="1.2">
              <hashTree>
                <HTTPSamplerProxy>
                  <stringProp name="HTTPSampler.domain">jmeter-hostonly.acme.example</stringProp>
                  <stringProp name="HTTPSampler.protocol">https</stringProp>
                  <stringProp name="HTTPSampler.path">/api/v1</stringProp>
                </HTTPSamplerProxy>
                <HTTPSamplerProxy>
                  <stringProp name="HTTPSampler.path">https://jmeter-live.acme.example/status</stringProp>
                </HTTPSamplerProxy>
                <HTTPSamplerProxy>
                  <stringProp name="HTTPSampler.domain">${tenant}.acme.example</stringProp>
                  <stringProp name="HTTPSampler.protocol">https</stringProp>
                  <stringProp name="HTTPSampler.path">/template</stringProp>
                </HTTPSamplerProxy>
              </hashTree>
            </jmeterTestPlan>
            """
        ).strip(),
        encoding="utf-8",
    )
    artillery_path = artifact_root / "artillery.yml"
    artillery_path.write_text(
        dedent(
            """
            config:
              target: artillery-hostonly.acme.example/api
              environments:
                preview:
                  target: https://${tenant}.acme.example/api
            scenarios:
              - name: status
                flow:
                  - get:
                      url: /status
                  - post:
                      url: https://artillery-live.acme.example/events
            """
        ).strip(),
        encoding="utf-8",
    )
    dredd_path = artifact_root / ".dredd.yml"
    dredd_path.write_text(
        dedent(
            """
            owner: dredd-owner@acme.example
            endpoint: dredd-hostonly.acme.example/api
            blueprint: https://dredd-docs.acme.example/openapi.yaml
            server: "npm run start:test"
            hooks:
              - ./hooks/*.js
            tenant_url: https://${tenant}.acme.example/template
            """
        ).strip(),
        encoding="utf-8",
    )
    schemathesis_path = artifact_root / ".schemathesis.toml"
    schemathesis_path.write_text(
        dedent(
            """
            owner = "schemathesis-owner@acme.example"
            schema = "https://schemathesis-schema.acme.example/openapi.json"
            base-url = "schemathesis-hostonly.acme.example/api"
            endpoint = "https://${tenant}.acme.example/template"
            """
        ).strip(),
        encoding="utf-8",
    )
    pactum_path = artifact_root / "pactum.config.js"
    pactum_path.write_text(
        dedent(
            """
            const pactum = require('pactum');

            pactum.request.setBaseUrl('pactum-base.acme.example/api');

            module.exports = {
              owner: 'pactum-owner@acme.example',
              baseUrl: 'https://pactum-config.acme.example/v1',
              endpoint: 'https://${tenant}.acme.example/template',
            };
            """
        ).strip(),
        encoding="utf-8",
    )
    pyresttest_path = artifact_root / "login.pyresttest.yaml"
    pyresttest_path.write_text(
        dedent(
            """
            owner: pyresttest-owner@acme.example
            config:
              variable_binds:
                base_url: pyresttest-env.acme.example/api
            tests:
              - name: host-only
                url: pyresttest-hostonly.acme.example/v1/users
              - name: live
                url: https://pyresttest-live.acme.example/v2/session
              - name: templated
                url: https://${tenant}.acme.example/template
            """
        ).strip(),
        encoding="utf-8",
    )
    gherkin_path = artifact_root / "api.feature"
    gherkin_path.write_text(
        dedent(
            """
            Feature: API
            Background:
              * url 'karate-hostonly.acme.example/api'
              * configure headers = { Accept: 'application/json' }
            Scenario: status
              Given path '/status'
              When method get
              And url 'https://karate-live.acme.example/events'
              * url 'https://${tenant}.acme.example/api'
            """
        ).strip(),
        encoding="utf-8",
    )
    k6_path = artifact_root / "k6-test.js"
    k6_path.write_text(
        dedent(
            """
            import http from 'k6/http';
            import ws from 'k6/ws';

            export const options = {
              target: 'k6-target.acme.example/api'
            };

            export default function () {
              http.get('k6-hostonly.acme.example/api');
              http.post("https://k6-live.acme.example/events", "{}");
              http.request("GET", "k6-request.acme.example/v1");
              http.get("https://${tenant}.acme.example/template");
              http.get("/relative");
              ws.connect("wss://k6-ws.acme.example/socket", {}, function () {});
            }
            """
        ).strip(),
        encoding="utf-8",
    )
    locust_path = artifact_root / "locustfile.py"
    locust_path.write_text(
        dedent(
            """
            from locust import HttpUser, task

            class WebsiteUser(HttpUser):
                host = "locust-hostonly.acme.example/api"

                @task
                def index(self):
                    self.client.get("/relative")
                    self.client.post("https://locust-live.acme.example/events")
                    self.client.request("GET", "locust-request.acme.example/v1")
                    self.client.get("https://${tenant}.acme.example/template")
            """
        ).strip(),
        encoding="utf-8",
    )
    tavern_path = artifact_root / "login.tavern.yaml"
    tavern_path.write_text(
        dedent(
            """
            test_name: Acme Tavern
            owner: tavern-owner@acme.example
            variables:
              base_url: tavern-env.acme.example/api
            stages:
              - name: host-only
                request:
                  url: tavern-hostonly.acme.example/v1/users
              - name: live
                request:
                  url: https://tavern-live.acme.example/v2/session
              - name: templated
                request:
                  url: https://${tenant}.acme.example/template
            """
        ).strip(),
        encoding="utf-8",
    )
    selenium_side_path = artifact_root / "login.side"
    selenium_side_path.write_text(
        json.dumps(
            {
                "id": "acme-side",
                "version": "2.0",
                "name": "Acme Selenium",
                "url": "selenium-base.acme.example/app",
                "owner": "selenium-owner@acme.example",
                "tests": [
                    {
                        "name": "login",
                        "commands": [
                            {"command": "open", "target": "/login"},
                            {"command": "click", "target": "css=.submit"},
                            {"command": "openWindow", "target": "reports.acme.example/dashboard"},
                            {
                                "command": "open",
                                "target": "https://${tenant}.acme.example/template",
                            },
                        ],
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    bundle_path = artifact_root / "api-client-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr(
            "bruno/login.bru",
            """
            meta {
              name: Login
              type: http
            }
            get {
              url: https://bruno.acme.example/login
            }
            headers {
              X-Owner: bruno-owner@acme.example
            }
            """.strip(),
        )
        zf.writestr(
            "specs/service.raml",
            """
            #%RAML 1.0
            title: Nested API
            baseUri: https://raml.acme.example/api
            annotationEndpoint: raml-hostonly.acme.example/internal
            contact: raml-owner@acme.example
            """.strip(),
        )
        zf.writestr(
            "specs/service.wsdl",
            """
            <definitions>
              <service>
                <port>
                  <soap:address xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" location="wsdl-hostonly.acme.example/service" />
                </port>
              </service>
              <documentation>wsdl-owner@acme.example https://wsdl.acme.example/service</documentation>
            </definitions>
            """.strip(),
        )
        zf.writestr(
            "specs/service.wadl",
            """
            <application>
              <resources base="wadl-hostonly.acme.example/api">
                <resource path="users" />
              </resources>
            </application>
            """.strip(),
        )
        zf.writestr(
            "collections/postman_collection",
            """
            {
              "info": {"name": "Postman"},
              "variable": [
                {"key": "baseUrl", "value": "postman-env.acme.example/api"},
                {"key": "docsUrl", "value": "https://postman-docs.acme.example/reference"}
              ],
              "environment": {
                "api_host": "postman-host-env.acme.example/status"
              },
              "item": [
                {"request": {"url": "https://postman.acme.example/request"}},
                {"request": {"url": {"protocol": "https", "host": ["postman-hostonly", "acme", "example"], "path": ["api", "v1"]}}}
              ],
              "owner": "postman-owner@acme.example"
            }
            """.strip(),
        )
        zf.writestr(
            "collections/insomnia_collection",
            """
            {
              "resources": [
                {"url": "https://insomnia.acme.example/graphql", "owner": "insomnia-owner@acme.example"},
                {"_type": "request", "url": "insomnia-hostonly.acme.example/graphql"},
                {
                  "_type": "environment",
                  "data": {
                    "base_url": "insomnia-env.acme.example/api",
                    "api_host": "insomnia-host-env.acme.example/status"
                  }
                }
              ]
            }
            """.strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 6
    assert summary.processed >= 6
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1
    assert summary.discovered_seeds >= 12

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "openapi-owner@acme.example" in emails
        assert "apib-owner@acme.example" in emails
        assert "arazzo-owner@acme.example" in emails
        assert "overlay-owner@acme.example" in emails
        assert "bruno-owner@acme.example" in emails
        assert "raml-owner@acme.example" in emails
        assert "wsdl-owner@acme.example" in emails
        assert "postman-owner@acme.example" in emails
        assert "insomnia-owner@acme.example" in emails
        assert "soapui-owner@acme.example" in emails
        assert "dredd-owner@acme.example" in emails
        assert "schemathesis-owner@acme.example" in emails
        assert "pactum-owner@acme.example" in emails
        assert "pyresttest-owner@acme.example" in emails
        assert "tavern-owner@acme.example" in emails
        assert "selenium-owner@acme.example" in emails

        seeds = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("https://openapi.acme.example/v1", "url") in seeds
        assert ("https://openapi-hostonly.acme.example/v2", "url") in seeds
        assert ("https://docs.openapi.acme.example/reference", "url") in seeds
        assert ("https://swagger-host.acme.example/api/v2", "url") in seeds
        assert ("https://apib-hostonly.acme.example/api", "url") in seeds
        assert ("https://arazzo-source.acme.example/openapi.yaml", "url") in seeds
        assert ("https://overlay-source.acme.example/openapi.yaml", "url") in seeds
        assert ("https://overlay-hostonly.acme.example/api", "url") in seeds
        assert ("https://bruno.acme.example/login", "url") in seeds
        assert ("https://raml.acme.example/api", "url") in seeds
        assert ("https://raml-hostonly.acme.example/internal", "url") in seeds
        assert ("https://wsdl.acme.example/service", "url") in seeds
        assert ("https://wsdl-hostonly.acme.example/service", "url") in seeds
        assert ("https://wadl-hostonly.acme.example/api", "url") in seeds
        assert ("https://postman.acme.example/request", "url") in seeds
        assert ("https://postman-hostonly.acme.example/api/v1", "url") in seeds
        assert ("https://postman-env.acme.example/api", "url") in seeds
        assert ("https://postman-env-file.acme.example/api", "url") in seeds
        assert ("https://postman-docs.acme.example/reference", "url") in seeds
        assert ("https://postman-host-env.acme.example/status", "url") in seeds
        assert ("https://insomnia.acme.example/graphql", "url") in seeds
        assert ("https://insomnia-hostonly.acme.example/graphql", "url") in seeds
        assert ("https://insomnia-env.acme.example/api", "url") in seeds
        assert ("https://insomnia-host-env.acme.example/status", "url") in seeds
        assert ("https://hoppscotch-hostonly.acme.example/api", "url") in seeds
        assert ("https://hoppscotch-env.acme.example/api", "url") in seeds
        assert ("https://thunder-hostonly.acme.example/api", "url") in seeds
        assert ("https://thunder-env.acme.example/api", "url") in seeds
        assert ("https://soapui-hostonly.acme.example/service", "url") in seeds
        assert ("https://soapui-live.acme.example/api", "url") in seeds
        assert ("https://soapui-attr.acme.example/rpc", "url") in seeds
        assert ("https://{tenant}.acme.example/api", "url") not in seeds
        assert ("https://jmeter-hostonly.acme.example/api/v1", "url") in seeds
        assert ("https://jmeter-live.acme.example/status", "url") in seeds
        assert ("https://${tenant}.acme.example/template", "url") not in seeds
        assert ("https://artillery-hostonly.acme.example/api", "url") in seeds
        assert ("https://artillery-live.acme.example/events", "url") in seeds
        assert ("https://${tenant}.acme.example/api", "url") not in seeds
        assert ("/status", "url") not in seeds
        assert ("https://dredd-hostonly.acme.example/api", "url") in seeds
        assert ("https://dredd-docs.acme.example/openapi.yaml", "url") in seeds
        assert ("https://schemathesis-schema.acme.example/openapi.json", "url") in seeds
        assert ("https://schemathesis-hostonly.acme.example/api", "url") in seeds
        assert ("https://pactum-base.acme.example/api", "url") in seeds
        assert ("https://pactum-config.acme.example/v1", "url") in seeds
        assert ("https://pyresttest-env.acme.example/api", "url") in seeds
        assert ("https://pyresttest-hostonly.acme.example/v1/users", "url") in seeds
        assert ("https://pyresttest-live.acme.example/v2/session", "url") in seeds
        assert ("https://karate-hostonly.acme.example/api", "url") in seeds
        assert ("https://karate-live.acme.example/events", "url") in seeds
        assert ("https://k6-target.acme.example/api", "url") in seeds
        assert ("https://k6-hostonly.acme.example/api", "url") in seeds
        assert ("https://k6-live.acme.example/events", "url") in seeds
        assert ("https://k6-request.acme.example/v1", "url") in seeds
        assert ("https://k6-ws.acme.example/socket", "url") in seeds
        assert ("https://locust-hostonly.acme.example/api", "url") in seeds
        assert ("https://locust-live.acme.example/events", "url") in seeds
        assert ("https://locust-request.acme.example/v1", "url") in seeds
        assert ("https://tavern-env.acme.example/api", "url") in seeds
        assert ("https://tavern-hostonly.acme.example/v1/users", "url") in seeds
        assert ("https://tavern-live.acme.example/v2/session", "url") in seeds
        assert ("https://${tenant}.acme.example/template", "url") not in seeds
        assert ("https://selenium-base.acme.example/app", "url") in seeds
        assert ("https://selenium-base.acme.example/login", "url") in seeds
        assert ("https://reports.acme.example/dashboard", "url") in seeds
        assert ("css=.submit", "url") not in seeds
        assert ("openapi-owner@acme.example", "email") in seeds
        assert ("apib-owner@acme.example", "email") in seeds
        assert ("arazzo-owner@acme.example", "email") in seeds
        assert ("overlay-owner@acme.example", "email") in seeds
        assert ("postman-owner@acme.example", "email") in seeds
        assert ("soapui-owner@acme.example", "email") in seeds
        assert ("dredd-owner@acme.example", "email") in seeds
        assert ("schemathesis-owner@acme.example", "email") in seeds
        assert ("pactum-owner@acme.example", "email") in seeds
        assert ("pyresttest-owner@acme.example", "email") in seeds
        assert ("tavern-owner@acme.example", "email") in seeds
        assert ("selenium-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-openapi-bucket") in cloud_assets
        assert ("firebase", "openapi-firebase") in cloud_assets
        assert ("supabase", "openapiworkspace") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[openapi_path.resolve().as_posix()]["format"] == "openapi"
        assert artifact_meta[openapi_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[swagger_path.resolve().as_posix()]["format"] == "swagger"
        assert artifact_meta[swagger_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[api_blueprint_path.resolve().as_posix()]["format"] == "api-blueprint"
        assert artifact_meta[api_blueprint_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[arazzo_path.resolve().as_posix()]["format"] == "arazzo"
        assert artifact_meta[arazzo_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[overlay_path.resolve().as_posix()]["format"] == "openapi-overlay"
        assert artifact_meta[overlay_path.resolve().as_posix()]["payload_count"] >= 1
        assert (
            artifact_meta[postman_env_path.resolve().as_posix()]["format"] == "postman-environment"
        )
        assert artifact_meta[postman_env_path.resolve().as_posix()]["payload_count"] >= 1
        assert (
            artifact_meta[hoppscotch_path.resolve().as_posix()]["format"] == "hoppscotch-collection"
        )
        assert artifact_meta[hoppscotch_path.resolve().as_posix()]["payload_count"] >= 1
        assert (
            artifact_meta[thunder_path.resolve().as_posix()]["format"]
            == "thunder-client-collection"
        )
        assert artifact_meta[thunder_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[soapui_path.resolve().as_posix()]["format"] == "soapui-project"
        assert artifact_meta[soapui_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[jmeter_path.resolve().as_posix()]["format"] == "jmeter-test-plan"
        assert artifact_meta[jmeter_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[artillery_path.resolve().as_posix()]["format"] == "artillery-config"
        assert artifact_meta[artillery_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[dredd_path.resolve().as_posix()]["format"] == "dredd-config"
        assert artifact_meta[dredd_path.resolve().as_posix()]["payload_count"] >= 1
        assert (
            artifact_meta[schemathesis_path.resolve().as_posix()]["format"] == "schemathesis-config"
        )
        assert artifact_meta[schemathesis_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[pactum_path.resolve().as_posix()]["format"] == "pactum-config"
        assert artifact_meta[pactum_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[pyresttest_path.resolve().as_posix()]["format"] == "pyresttest"
        assert artifact_meta[pyresttest_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[gherkin_path.resolve().as_posix()]["format"] == "gherkin-feature"
        assert artifact_meta[gherkin_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[k6_path.resolve().as_posix()]["format"] == "k6-script"
        assert artifact_meta[k6_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[locust_path.resolve().as_posix()]["format"] == "locustfile"
        assert artifact_meta[locust_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[tavern_path.resolve().as_posix()]["format"] == "tavern-api-test"
        assert artifact_meta[tavern_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[selenium_side_path.resolve().as_posix()]["format"] == "selenium-side"
        assert artifact_meta[selenium_side_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 5
    finally:
        con.close()


