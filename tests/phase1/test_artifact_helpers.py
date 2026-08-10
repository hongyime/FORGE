from __future__ import annotations

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_artifact_name,
    _classify_remote_artifact_candidate,
    _classify_remote_artifact_url,
    _classify_seed_value,
    _extract_artifact_relative_route_urls,
    _normalize_root_domain,
    _select_remote_artifact_filename,
    _suffix_from_content_type,
)


def test_classify_seed_value_recognizes_archive_style_mobile_bundle_urls() -> None:
    assert (
        _classify_seed_value("https://downloads.acme.example/client.xapk?download=1") == "apk_url"
    )
    assert (
        _classify_seed_value("https://downloads.acme.example/client.apkm?download=1") == "apk_url"
    )
    assert (
        _classify_seed_value("https://downloads.acme.example/client.apks?download=1") == "apk_url"
    )
    assert (
        _classify_seed_value(
            "https://id.acme.example/.well-known/webfinger?resource=acct:user@acme.example"
        )
        == "url"
    )
    assert (
        _classify_remote_artifact_url("https://acme.example/.well-known/security.txt") == "config"
    )
    for metadata_url in (
        "https://acme.example/humans.txt",
        "https://acme.example/ads.txt",
        "https://acme.example/app-ads.txt",
        "https://acme.example/sellers.json",
        "https://acme.example/llms.txt",
        "https://acme.example/ai.txt",
        "https://acme.example/ai-plugin.json",
        "https://acme.example/manifest",
        "https://acme.example/manifest.json",
        "https://acme.example/browserconfig.xml",
        "https://acme.example/.well-known/assetlinks.json",
        "https://acme.example/_redirects",
        "https://acme.example/_headers",
        "https://acme.example/_routes.json",
    ):
        assert _classify_remote_artifact_url(metadata_url) == "config"
    assert _classify_artifact_name("_redirects") == "config"
    assert _classify_artifact_name("_headers") == "config"
    assert _classify_artifact_name("_routes.json") == "config"
    assert (
        _select_remote_artifact_filename(
            42,
            "https://acme.example/manifest",
            "config",
            content_type="application/manifest+json",
        )
        == "webmanifest"
    )
    assert _classify_remote_artifact_url("https://storage.acme.example/.kube/config") == "config"
    assert (
        _select_remote_artifact_filename(
            43,
            "https://storage.acme.example/.kube/config",
            "config",
        )
        == "kubeconfig"
    )


def test_normalize_root_domain_handles_common_second_level_public_suffixes() -> None:
    assert _normalize_root_domain("portal.acme.example") == "acme.example"
    assert _normalize_root_domain("portal.acme.co.uk") == "acme.co.uk"
    assert _normalize_root_domain("api.acme.com.sg") == "acme.com.sg"


def test_classify_remote_artifact_url_recognizes_7z_archives() -> None:
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/intel-drop.7z?sig=abc")
        == "archive"
    )


def test_security_scanner_config_artifact_format_labels_are_source_aware() -> None:
    assert _artifact_format_label(".github/codeql/codeql-config.yml") == "codeql-config"
    assert _artifact_format_label("codeql.yml") == "codeql-config"
    assert _artifact_format_label("sonar-project.properties") == "sonar-project"
    assert _artifact_format_label("sonar-project.yaml") == "sonar-project"
    assert _artifact_format_label(".pre-commit-config.yaml") == "pre-commit-config"
    assert _artifact_format_label(".pre-commit-hooks.yaml") == "pre-commit-hooks"
    assert _artifact_format_label("trivy.yaml") == "trivy-config"
    assert _artifact_format_label(".gitleaks.toml") == "gitleaks-config"
    assert _artifact_format_label(".semgrep/config.yml") == "semgrep-config"
    assert _artifact_format_label(".trufflehog.yml") == "trufflehog-config"
    assert _artifact_format_label(".detect-secrets.toml") == "detect-secrets-config"
    assert _artifact_format_label("secretlint.config.json") == "secretlint-config"
    assert _artifact_format_label("osv-scanner.toml") == "osv-scanner-config"
    assert _artifact_format_label(".checkov.yml") == "checkov-config"
    assert _artifact_format_label("tfsec.json") == "tfsec-config"
    assert _artifact_format_label("terrascan.toml") == "terrascan-config"
    assert _artifact_format_label("kics.config") == "kics-config"
    assert _artifact_format_label("nuclei-config.yaml") == "nuclei-config"


def test_kubernetes_annotation_bare_hosts_feed_orchestration_recursion(tmp_path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/upstream-vhost: upstream.acme.example
    haproxy-ingress.github.io/server-alias: alias.acme.example
  labels:
    app.kubernetes.io/name: label-noise.acme.example
spec:
  rules:
    - host: ingress.acme.example
""".strip()

    assert processor._orchestration_structured_payload_text(payload, source_hint="notes.yaml") == ""
    assert processor._orchestration_structured_payload_text(
        payload,
        source_hint="k8s/ingress.yaml",
    ).splitlines() == [
        "http://upstream.acme.example",
        "http://ingress.acme.example",
        "http://alias.acme.example",
    ]


def test_helm_lock_repositories_feed_orchestration_recursion(tmp_path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = """
dependencies:
  - name: redis
    repository: https://charts.bitnami.com/bitnami
  - name: templated
    repository: https://${HELM_REPO}/charts
""".strip()

    assert processor._orchestration_structured_payload_text(
        payload,
        source_hint="Chart.lock",
    ).splitlines() == ["https://charts.bitnami.com/bitnami"]
    assert (
        processor._orchestration_structured_payload_text(
            payload,
            source_hint="notes.yaml",
        )
        == ""
    )


def test_recon_tool_output_artifact_format_labels_are_source_aware() -> None:
    assert _artifact_format_label("subfinder.jsonl") == "subfinder-output"
    assert _artifact_format_label("subfinder-results.jsonl") == "subfinder-output"
    assert _artifact_format_label("amass.json") == "amass-output"
    assert _artifact_format_label("massdns-results.txt") == "massdns-output"
    assert _artifact_format_label("puredns-resolve.txt") == "puredns-output"
    assert _artifact_format_label("dnsrecon.json") == "dnsrecon-output"
    assert _artifact_format_label("dnsenum-report.xml") == "dnsenum-output"
    assert _artifact_format_label("subjack-takeovers.json") == "subjack-output"
    assert _artifact_format_label("subzy-results.json") == "subzy-output"
    assert _artifact_format_label("httpx-output.jsonl") == "httpx-output"
    assert _artifact_format_label("katana.jsonl") == "katana-output"
    assert _artifact_format_label("gau.txt") == "gau-output"
    assert _artifact_format_label("waybackurls.txt") == "waybackurls-output"
    assert _artifact_format_label("nuclei-results.jsonl") == "nuclei-output"
    assert _artifact_format_label("naabu-output.jsonl") == "naabu-output"
    assert _artifact_format_label("ffuf-report.json") == "ffuf-output"
    assert _artifact_format_label("feroxbuster-results.json") == "feroxbuster-output"
    assert _artifact_format_label("dirsearch-report.json") == "dirsearch-output"
    assert _artifact_format_label("zap-scan.json") == "zap-output"
    assert _artifact_format_label("whatweb-report.json") == "whatweb-output"
    assert _artifact_format_label("wafw00f-results.json") == "wafw00f-output"
    assert _artifact_format_label("sslscan-results.xml") == "sslscan-output"
    assert _artifact_format_label("testssl-report.json") == "testssl-output"
    assert _artifact_format_label("sslyze-results.json") == "sslyze-output"
    assert _artifact_format_label("rustscan-output.json") == "rustscan-output"
    assert _artifact_format_label("wpscan-report.json") == "wpscan-output"
    assert _artifact_format_label("cmsmap-output.txt") == "cmsmap-output"
    assert _artifact_format_label("droopescan-results.json") == "droopescan-output"
    assert _artifact_format_label("joomscan-report.txt") == "joomscan-output"
    assert _artifact_format_label("cmseek-result.json") == "cmseek-output"
    assert _artifact_format_label("gowitness-report.json") == "gowitness-output"
    assert _artifact_format_label("eyewitness-results.json") == "eyewitness-output"
    assert _artifact_format_label("aquatone-urls.txt") == "aquatone-output"
    assert _artifact_format_label("urlscan-results.json") == "urlscan-output"
    assert _artifact_format_label("shodan-export.json") == "shodan-output"
    assert _artifact_format_label("censys-hosts.json") == "censys-output"
    assert _artifact_format_label("fofa-results.json") == "fofa-output"
    assert _artifact_format_label("zoomeye-output.json") == "zoomeye-output"
    assert _artifact_format_label("securitytrails-subdomains.json") == "securitytrails-output"
    assert _artifact_format_label("binaryedge-report.json") == "binaryedge-output"
    assert _artifact_format_label("builtwith-export.json") == "builtwith-output"


def test_api_docs_extensionless_routes_classify_as_passive_config_artifacts() -> None:
    assert _classify_remote_artifact_url("https://api.acme.example/api-docs") == "config"
    assert _classify_remote_artifact_url("https://api.acme.example/v3/api-docs") == "config"
    assert _classify_remote_artifact_url("https://api.acme.example/v3/api_docs") == "config"
    assert _extract_artifact_relative_route_urls(
        """
        const specA = "/api-docs";
        const specB = "/v3/api-docs";
        const specC = "/v3/api_docs";
        const ignored = "/v3/status";
        """,
        base_url="https://api.acme.example/static/app.js",
    ) == [
        "https://api.acme.example/api-docs",
        "https://api.acme.example/v3/api-docs",
        "https://api.acme.example/v3/api_docs",
    ]
