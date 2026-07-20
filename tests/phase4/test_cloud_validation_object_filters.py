from __future__ import annotations

from forge.phase4 import cloud_validate


def test_static_site_helper_recognizes_framework_build_artifacts() -> None:
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "_next/static/chunks/app-4b2fe9aa.js"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "_nuxt/entry.8f3ea4bd.js"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "static/js/main.8f3ea4bd.js"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "static/chunks/webpack-3f1a2b.js"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "chunks/framework-41d8c3a2.js"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "static/assets/logo-7bb2d.svg"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "public/build/app-91af22.css"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "assets/index-8f3ea4bd.js"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "dist/assets/index-8f3ea4bd.js"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "service-worker.js"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "favicon-32x32.png"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("vercel.json")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("netlify.toml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("render.yaml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("fly.toml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("railway.toml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("staticwebapp.config.json")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("apphosting.yaml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("heroku.yml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("heroku-app.json")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("static.json")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("_redirects")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("_headers")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "build-manifest.json"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("_routes.json")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("css/site.css")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("js/app.js")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("images/logo.svg")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("fonts/inter.woff2")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("main.css")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("app-ads.txt")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("sellers.json")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("manifest")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "google1234567890abcdef.html"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("BingSiteAuth.xml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "yandex_1234567890abcdef.html"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "baidu_verify_1234567890abcdef.html"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "pinterest-1234567890abcdef.html"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "facebook-domain-verification.html"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/apple-developer-merchantid-domain-association"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("sitemap_index.xml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("post-sitemap.xml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("feed.xml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("rss.xml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("atom.xml")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/openid-configuration"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/oauth-authorization-server"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/oauth-protected-resource"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/openid-federation"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/related-website-set.json"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/first-party-set.json"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/uma2-configuration"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(".well-known/jwks.json")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(".well-known/webfinger")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(".well-known/mta-sts.txt")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(".well-known/did.json")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/matrix/server"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/change-password"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        "apple-touch-icon-precomposed.png"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/assetlinks.json"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/apple-app-site-association"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/acme-challenge/a1b2c3d4"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name(
        ".well-known/pki-validation/fileauth.txt"
    )
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("_worker.js")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("CNAME")
    assert cloud_validate.BaseCloudValidator._is_common_static_site_object_name("firebase.json")


def test_repository_metadata_helper_downgrades_only_metadata_names() -> None:
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "services/api/package.json"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "frontend/package-lock.json"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "python/pyproject.toml"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "requirements-dev.txt"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "runtime/.nvmrc"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "services/api/.python-version"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        ".tool-versions"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "frontend/tsconfig.app.json"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "frontend/vite.config.ts"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "frontend/tailwind.config.js"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "frontend/postcss.config.cjs"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "frontend/webpack.config.mjs"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "deploy/chart/Chart.yaml"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "deploy/chart/Chart.lock"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "deploy/kustomization.yaml"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "deploy/helmfile.yaml"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "deploy/skaffold.yml"
    )
    assert cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "deploy/Kptfile"
    )
    assert not cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "deploy/values.yaml"
    )
    assert not cloud_validate.BaseCloudValidator._is_common_repository_metadata_object_name(
        "secrets/prod-values.yaml"
    )
    assert cloud_validate.BaseCloudValidator._meaningful_object_names(
        [
            "archive/",
            "README.md",
            "package.json",
            "services/api/pyproject.toml",
            "requirements-dev.txt",
            "runtime/.nvmrc",
            "services/api/.python-version",
            ".tool-versions",
            "frontend/tsconfig.app.json",
            "frontend/vite.config.ts",
            "frontend/tailwind.config.js",
            "frontend/postcss.config.cjs",
            "frontend/webpack.config.mjs",
            "deploy/chart/Chart.yaml",
            "deploy/chart/Chart.lock",
            "deploy/kustomization.yaml",
            "deploy/helmfile.yaml",
            "deploy/skaffold.yml",
            "deploy/Kptfile",
        ]
    ) == []
    assert cloud_validate.BaseCloudValidator._meaningful_object_names(
        ["README.md", "package.json", "exports/customer-data.csv"]
    ) == ["exports/customer-data.csv"]
    assert cloud_validate.BaseCloudValidator._meaningful_object_names(
        ["frontend/vite.config.ts", ".env", "config/secrets.json"]
    ) == [".env", "config/secrets.json"]
    assert cloud_validate.BaseCloudValidator._meaningful_object_names(
        ["deploy/chart/Chart.yaml", "deploy/values.yaml", "secrets/prod-values.yaml"]
    ) == ["deploy/values.yaml", "secrets/prod-values.yaml"]


def test_filesystem_metadata_helper_downgrades_only_metadata_names() -> None:
    assert cloud_validate.BaseCloudValidator._is_common_filesystem_metadata_object_name(
        "exports/.DS_Store"
    )
    assert cloud_validate.BaseCloudValidator._is_common_filesystem_metadata_object_name(
        "media/Thumbs.db"
    )
    assert cloud_validate.BaseCloudValidator._is_common_filesystem_metadata_object_name(
        "desktop.ini"
    )
    assert cloud_validate.BaseCloudValidator._is_common_filesystem_metadata_object_name(
        "__MACOSX/._report.pdf"
    )
    assert cloud_validate.BaseCloudValidator._meaningful_object_names(
        [
            "archive/",
            "exports/.DS_Store",
            "media/Thumbs.db",
            "desktop.ini",
            "__MACOSX/._report.pdf",
        ]
    ) == []
    assert cloud_validate.BaseCloudValidator._meaningful_object_names(
        ["Thumbs.db", "reports/final.pdf"]
    ) == ["reports/final.pdf"]


def test_api_documentation_helper_downgrades_only_documentation_names() -> None:
    assert cloud_validate.BaseCloudValidator._is_common_api_documentation_object_name(
        "openapi.json"
    )
    assert cloud_validate.BaseCloudValidator._is_common_api_documentation_object_name(
        "docs/openapi/swagger.yaml"
    )
    assert cloud_validate.BaseCloudValidator._is_common_api_documentation_object_name(
        "swagger-ui/swagger-ui-bundle.js"
    )
    assert cloud_validate.BaseCloudValidator._is_common_api_documentation_object_name(
        "api-docs/acme.postman_collection.json"
    )
    assert cloud_validate.BaseCloudValidator._is_common_api_documentation_object_name(
        "redoc/redoc-static.html"
    )
    assert cloud_validate.BaseCloudValidator._is_common_api_documentation_object_name(
        "docs/graphql/schema.graphql"
    )
    assert cloud_validate.BaseCloudValidator._is_common_api_documentation_object_name(
        "graphql/introspection.json"
    )
    assert cloud_validate.BaseCloudValidator._is_common_api_documentation_object_name(
        "soap/service.wsdl"
    )
    assert cloud_validate.BaseCloudValidator._is_common_api_documentation_object_name(
        "api/service.wadl"
    )
    assert not cloud_validate.BaseCloudValidator._is_common_api_documentation_object_name(
        "exports/customer-records.csv"
    )
    assert not cloud_validate.BaseCloudValidator._is_common_api_documentation_object_name(
        "api-docs/customer-records.csv"
    )
    assert cloud_validate.BaseCloudValidator._meaningful_object_names(
        [
            "openapi.json",
            "docs/openapi/swagger.yaml",
            "docs/graphql/schema.graphql",
            "soap/service.wsdl",
            "swagger-ui/swagger-ui-bundle.js",
            "api-docs/acme.postman_collection.json",
        ]
    ) == []
    assert cloud_validate.BaseCloudValidator._meaningful_object_names(
        ["openapi.json", "exports/customer-records.csv"]
    ) == ["exports/customer-records.csv"]
