from __future__ import annotations

from forge.engagement_orchestrator import (
    _artifact_format_label,
    _classify_artifact_name,
    _select_remote_artifact_filename,
    _suffix_from_content_type,
)


def test_api_spec_and_client_collection_content_types_map_to_config_artifact_suffixes() -> None:
    content_type_suffixes = {
        "application/vnd.oai.openapi+json": ".openapi",
        "application/vnd.oai.openapi+yaml; charset=utf-8": ".openapi",
        "application/openapi+json": ".openapi",
        "application/vnd.apiblueprint": ".apib",
        "application/vnd.oai.arazzo+yaml": ".arazzo",
        "application/vnd.oai.overlay+json": ".openapi-overlay",
        "application/vnd.swagger+json": ".swagger",
        "application/swagger+yaml": ".swagger",
        "application/graphql": ".graphql",
        "text/x-graphql": ".graphql",
        "application/raml+yaml": ".raml",
        "application/wsdl+xml": ".wsdl",
        "text/x-api-blueprint": ".apib",
        "text/x-arazzo": ".arazzo",
        "text/x-openapi-overlay": ".openapi-overlay",
        "application/vnd.postman.collection+json": ".postman_collection",
        "application/vnd.insomnia.export+json": ".insomnia_collection",
        "application/x-insomnia-export+json": ".insomnia_collection",
        "application/pact+json": ".pact.json",
        "application/vnd.pact+json": ".pact.json",
        "application/vnd.selenium.side+json": ".side",
        "application/x-selenium-side": ".side",
        "application/x-jmeter-test-plan": ".jmx",
        "text/x-jmeter": ".jmx",
        "application/x-hurl": ".hurl",
        "text/x-hurl": ".hurl",
        "application/x-k6": ".js",
        "text/x-k6": ".js",
        "text/x-gherkin": ".feature",
        "application/x-gherkin": ".feature",
        "application/bruno": ".bru",
        "text/x-bruno": ".bru",
        "application/x-charles-session-json": ".chlsj",
    }

    for content_type, expected_suffix in content_type_suffixes.items():
        suffix = _suffix_from_content_type(content_type)
        assert suffix == expected_suffix
        selected_name = _select_remote_artifact_filename(
            42,
            "https://api.acme.example/download",
            "config",
            content_type=content_type,
        )
        assert selected_name == f"artifact-42{expected_suffix}"
        assert _classify_artifact_name(selected_name) == "config"

    assert _artifact_format_label("acme.postman_environment.json") == "postman-environment"
    assert _artifact_format_label("acme.insomnia_environment.json") == "insomnia-environment"
    assert _artifact_format_label("hoppscotch_collection.json") == "hoppscotch-collection"
    assert _artifact_format_label("hoppscotch_environment.json") == "hoppscotch-environment"
    assert _artifact_format_label("thunder-collection.json") == "thunder-client-collection"
    assert _artifact_format_label("thunder-environment.json") == "thunder-client-environment"
    assert _artifact_format_label("soapui-project.xml") == "soapui-project"
    assert _artifact_format_label("acme-readyapi-workspace.xml") == "soapui-project"
    assert _artifact_format_label("apiary.apib") == "api-blueprint"
    assert _artifact_format_label("service.api-blueprint") == "api-blueprint"
    assert _artifact_format_label("workflow.arazzo") == "arazzo"
    assert _artifact_format_label("arazzo.yaml") == "arazzo"
    assert _artifact_format_label("petstore.openapi-overlay") == "openapi-overlay"
    assert _artifact_format_label("openapi-overlay.yaml") == "openapi-overlay"
    assert _artifact_format_label("login.side") == "selenium-side"
    assert _artifact_format_label("selenium-project.json") == "selenium-side"
    assert _artifact_format_label("login.tavern.yaml") == "tavern-api-test"
    assert _artifact_format_label(".dredd.yml") == "dredd-config"
    assert _artifact_format_label("dredd.json") == "dredd-config"
    assert _artifact_format_label(".schemathesis.toml") == "schemathesis-config"
    assert _artifact_format_label("schemathesis.yaml") == "schemathesis-config"
    assert _artifact_format_label("pactum.config.js") == "pactum-config"
    assert _artifact_format_label(".pactumrc.yaml") == "pactum-config"
    assert _artifact_format_label("login.pyresttest.yaml") == "pyresttest"
    assert _artifact_format_label("api.resttest.yml") == "pyresttest"
    assert _artifact_format_label("requests/status.hurl") == "hurl"
    assert _artifact_format_label("burp-site-map.xml") == "burp-site-map"
    assert _artifact_format_label("browser-session.chlsj") == "charles-session-json"
    assert _artifact_format_label("pact.json") == "pact-contract"
    assert _artifact_format_label("pact.yml") == "pact-contract"
    assert _artifact_format_label("pacts/acme-web-acme-api.json") == "pact-contract"
    assert _artifact_format_label("pacts/acme-web-acme-api") == "pact-contract"
    assert _artifact_format_label("impact-contractor.json") == "json"
    assert _artifact_format_label("compact-contraction.yaml") == "yaml"
    assert _artifact_format_label("pacts/LICENSE") == "license"
    assert (
        _select_remote_artifact_filename(
            99,
            "https://downloads.acme.example/pacts/LICENSE",
            "config",
        )
        == "LICENSE"
    )
    assert (
        _artifact_format_label(".well-known/related-website-set.json") == "related-website-set.json"
    )
    assert _artifact_format_label(".well-known/first-party-set.json") == "first-party-set.json"
    assert _artifact_format_label("load-test.jmx") == "jmeter-test-plan"
    assert _artifact_format_label("k6-test.js") == "k6-script"
    assert _artifact_format_label("load-test.k6.js") == "k6-script"
    assert _artifact_format_label("locustfile.py") == "locustfile"
    assert _artifact_format_label("locust.conf") == "locustfile"
    assert _artifact_format_label("artillery.yml") == "artillery-config"
    assert _artifact_format_label(".artilleryrc.yaml") == "artillery-config"
    assert _artifact_format_label("api.feature") == "gherkin-feature"
    assert _artifact_format_label("vite.config.ts") == "vite-config"
    assert _artifact_format_label("webpack.config.mjs") == "webpack-config"
    assert _artifact_format_label("rollup.config.js") == "rollup-config"
    assert _artifact_format_label("rspack.config.ts") == "rspack-config"
    assert _artifact_format_label("rsbuild.config.mjs") == "rsbuild-config"
    assert _artifact_format_label("vitest.config.ts") == "vitest-config"
    assert _artifact_format_label("jest.config.cjs") == "jest-config"
    assert _artifact_format_label("karma.conf.js") == "karma-config"
    assert _artifact_format_label("next.config.js") == "next-config"
    assert _artifact_format_label("nuxt.config.mjs") == "nuxt-config"
    assert _artifact_format_label("astro.config.mjs") == "astro-config"
    assert _artifact_format_label("svelte.config.js") == "svelte-config"
    assert _artifact_format_label("remix.config.cjs") == "remix-config"
    assert _artifact_format_label("app.config.ts") == "expo-app-config"
    assert _artifact_format_label("deno.json") == "deno-config"
    assert _artifact_format_label("deno.jsonc") == "deno-config"
    assert _artifact_format_label("deno.lock") == "deno-lock"
    assert _artifact_format_label("import_map.json") == "deno-import-map"
    assert _artifact_format_label("import-map.jsonc") == "deno-import-map"
    assert _artifact_format_label("jsr.json") == "jsr-config"
    assert _artifact_format_label("mobile/app.json") == "expo-app-config"
    assert _artifact_format_label("eas.json") == "expo-eas-config"
    assert _artifact_format_label("capacitor.config.ts") == "capacitor-config"
    assert _artifact_format_label("capacitor.config.json") == "capacitor-config"
    assert _artifact_format_label("ionic.config.json") == "ionic-config"
    assert _artifact_format_label("cordova/config.xml") == "cordova-config"
    assert _artifact_format_label("config.xml") == "xml"
    assert _artifact_format_label("firebase.json") == "firebase-hosting-config"
    assert _artifact_format_label("vercel.json") == "vercel-config"
    assert _artifact_format_label("netlify.toml") == "netlify-config"
    assert _artifact_format_label("turbo.json") == "turbo-config"
    assert _artifact_format_label("nx.json") == "nx-config"
    assert _artifact_format_label("render.yaml") == "render-config"
    assert _artifact_format_label("fly.toml") == "fly-config"
    assert _artifact_format_label("railway.toml") == "railway-config"
    assert _artifact_format_label("staticwebapp.config.json") == "azure-static-web-app-config"
    assert _artifact_format_label("apphosting.yaml") == "firebase-app-hosting-config"
    assert _artifact_format_label("amplify.yml") == "amplify-config"
    assert _artifact_format_label("heroku.yml") == "heroku-config"
    assert _artifact_format_label("heroku/app.json") == "heroku-app-json"
    assert _artifact_format_label("heroku-app.json") == "heroku-app-json"
    assert _artifact_format_label("static.json") == "static-json-config"
    assert _artifact_format_label("_redirects") == "static-hosting-redirects"
    assert _artifact_format_label("_headers") == "static-hosting-headers"
    assert _artifact_format_label("_routes.json") == "cloudflare-pages-routes"
    assert _artifact_format_label("app.json") == "json"
    assert _artifact_format_label(".storybook/main.ts") == "storybook-config"
    assert _artifact_format_label("playwright.config.ts") == "playwright-config"
    assert _artifact_format_label("storage-state.json") == "playwright-storage-state"
    assert _artifact_format_label("playwright/.auth/auth-state.json") == "playwright-storage-state"
    assert _artifact_format_label("cypress.env.json") == "cypress-env"
    assert _artifact_format_label("browser/localStorage.json") == "browser-storage-state"
    assert _artifact_format_label("cypress.config.mjs") == "cypress-config"
    assert _artifact_format_label("testcafe.config.ts") == "testcafe-config"
    assert _artifact_format_label(".testcaferc.json") == "testcafe-config"
    assert _artifact_format_label("wdio.conf.js") == "webdriverio-config"
    assert _artifact_format_label("nightwatch.conf.cjs") == "nightwatch-config"
    assert _artifact_format_label(".graphqlrc.yml") == "graphql-config"
    assert _artifact_format_label("graphql.config.json") == "graphql-config"
    assert _artifact_format_label("graphql-codegen.yml") == "graphql-codegen"
    assert _artifact_format_label(".graphql-codegen.ts") == "graphql-codegen"
    assert _artifact_format_label("apollo.config.js") == "apollo-config"
    assert _artifact_format_label("apollo.config.json") == "apollo-config"
    assert _artifact_format_label("nginx.conf") == "nginx-config"
    assert _artifact_format_label("nginx/default.conf") == "nginx-config"
    assert _artifact_format_label("apache/httpd.conf") == "apache-config"
    assert _artifact_format_label("haproxy.cfg") == "haproxy-config"
    assert _artifact_format_label("traefik.yml") == "traefik-config"
    assert _artifact_format_label("envoy.yaml") == "envoy-config"
    assert _artifact_format_label("kong.yml") == "kong-config"
    assert _artifact_format_label("Caddyfile") == "caddyfile"
    assert _artifact_format_label("docker-compose.yml") == "docker-compose"
    assert _artifact_format_label("docker-compose.override.yml") == "docker-compose"
    assert _artifact_format_label("docker-compose.dev.yml") == "docker-compose"
    assert _artifact_format_label("docker-compose.prod.yaml") == "docker-compose"
    assert _artifact_format_label("compose.yaml") == "docker-compose"
    assert _artifact_format_label("compose.override.yaml") == "docker-compose"
    assert _artifact_format_label("compose.local.yml") == "docker-compose"
    assert _artifact_format_label("compose.test.yaml") == "docker-compose"
    assert _artifact_format_label("not-compose.override.yml") == "yml"
    assert _artifact_format_label("not-compose.prod.yml") == "yml"
    assert _artifact_format_label("my-compose.dev.yml") == "yml"
    assert _artifact_format_label("compose.production.backup.yml") == "yml"
    assert _artifact_format_label("Chart.yaml") == "helm-chart"
    assert _artifact_format_label("Chart.lock") == "helm-lock"
    assert _artifact_format_label("charts/acme/values.yaml") == "helm-values"
    assert _artifact_format_label("acme-portal-1.2.3.tgz/acme-portal/values.yaml") == "helm-values"
    assert _artifact_format_label("acme-portal/values.yaml") == "yaml"
    assert _artifact_format_label("k8s/ingress.yaml") == "kubernetes-manifest"
    assert _artifact_format_label("manifests/httproute.yaml") == "kubernetes-manifest"
    assert _artifact_format_label("package.json") == "npm-package-manifest"
    assert _artifact_format_label("package-lock.json") == "npm-package-lock"
    assert _artifact_format_label("npm-shrinkwrap.json") == "npm-shrinkwrap"
    assert _artifact_format_label("yarn.lock") == "yarn-lock"
    assert _artifact_format_label("pnpm-lock.yaml") == "pnpm-lock"
    assert _artifact_format_label("pnpm-workspace.yaml") == "pnpm-workspace"
    assert _artifact_format_label("bun.lockb") == "bun-lockb"
    assert _artifact_format_label("Pipfile.lock") == "pipfile-lock"
    assert _artifact_format_label("poetry.lock") == "poetry-lock"
    assert _artifact_format_label("uv.lock") == "uv-lock"
    assert _artifact_format_label("pyproject.toml") == "pyproject"
    assert _artifact_format_label("requirements-dev.txt") == "python-requirements"
    assert _artifact_format_label("requirements.in") == "python-requirements-input"
    assert _artifact_format_label("constraints-prod.txt") == "python-constraints"
    assert _artifact_format_label("Cargo.lock") == "cargo-lock"
    assert _artifact_format_label("go.mod") == "go-mod"
    assert _artifact_format_label("go.sum") == "go-sum"
    assert _artifact_format_label("go.work") == "go-work"
    assert _artifact_format_label("composer.json") == "composer-manifest"
    assert _artifact_format_label("composer.lock") == "composer-lock"
    assert _artifact_format_label("Gemfile.lock") == "bundler-lock"
    assert _artifact_format_label("Podfile.lock") == "cocoapods-lock"
    assert _artifact_format_label("Cartfile.resolved") == "carthage-resolved"
    assert _artifact_format_label("Package.resolved") == "swift-package-resolved"
    assert _artifact_format_label("gradle.lockfile") == "gradle-lockfile"
