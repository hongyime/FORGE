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
    assert _classify_seed_value("https://downloads.acme.example/client.xapk?download=1") == "apk_url"
    assert _classify_seed_value("https://downloads.acme.example/client.apkm?download=1") == "apk_url"
    assert _classify_seed_value("https://downloads.acme.example/client.apks?download=1") == "apk_url"
    assert (
        _classify_seed_value(
            "https://id.acme.example/.well-known/webfinger?resource=acct:user@acme.example"
        )
        == "url"
    )
    assert (
        _classify_remote_artifact_url("https://acme.example/.well-known/security.txt")
        == "config"
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
    assert _classify_remote_artifact_url("https://downloads.acme.example/intel-drop.7z?sig=abc") == "archive"


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

    assert (
        processor._orchestration_structured_payload_text(payload, source_hint="notes.yaml")
        == ""
    )
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
    assert processor._orchestration_structured_payload_text(
        payload,
        source_hint="notes.yaml",
    ) == ""


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


def test_classify_remote_artifact_url_recognizes_debian_package_archives() -> None:
    assert _classify_remote_artifact_url("https://downloads.acme.example/acme-agent_1.0.0_all.deb") == "archive"
    assert _classify_remote_artifact_url("https://downloads.acme.example/acme-installer.udeb?dl=1") == "archive"
    assert _classify_remote_artifact_url("https://downloads.acme.example/acme-router.ipk?token=abc") == "archive"
    assert _classify_remote_artifact_url("https://downloads.acme.example/initramfs.cpio?download=1") == "archive"
    assert _classify_remote_artifact_url("https://downloads.acme.example/acme-agent-1.0.0.x86_64.rpm") == "document"


def test_classify_remote_artifact_candidate_uses_safe_download_metadata() -> None:
    extensionless_url = "https://downloads.acme.example/download?artifact=agent"
    assert _classify_remote_artifact_url(extensionless_url) is None
    assert (
        _classify_remote_artifact_candidate(
            extensionless_url,
            content_type="application/x-rpm",
        )
        == "document"
    )
    assert (
        _classify_remote_artifact_candidate(
            extensionless_url,
            content_disposition='attachment; filename="agent.apk"',
        )
        == "apk"
    )
    assert (
        _classify_remote_artifact_candidate(
            extensionless_url,
            download_filename="support-bundle.7z",
        )
        == "archive"
    )


def test_classify_remote_artifact_url_recognizes_firmware_binary_artifacts() -> None:
    assert _classify_remote_artifact_url("https://downloads.acme.example/router-firmware.bin") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/native-agent.elf?download=1") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/router.fw") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/router.rom") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/router.img?dl=1") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/acme-installer.msi") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/acme-installer.pkg?dl=1") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/prod.tfplan") == "document"
    assert _classify_remote_artifact_url("https://data.acme.example/export/customers.parquet") == "document"
    assert _classify_remote_artifact_url("https://data.acme.example/export/audit.orc?dl=1") == "document"
    assert _classify_remote_artifact_url("https://data.acme.example/export/events.avro") == "document"
    assert _classify_remote_artifact_url("https://data.acme.example/export/features.arrow") == "document"
    assert _classify_remote_artifact_url("https://data.acme.example/export/features.feather") == "document"
    assert _classify_remote_artifact_url("https://data.acme.example/export/research.hdf5") == "document"


def test_classify_remote_artifact_url_recognizes_keystore_binary_artifacts() -> None:
    assert _classify_remote_artifact_url("https://downloads.acme.example/release.keystore") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/upload.jks?dl=1") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/truststore.jceks") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/client.p12") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/client.pfx?token=abc") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/mobile.bks") == "document"


def test_classify_remote_artifact_url_recognizes_certificate_binary_artifacts() -> None:
    assert _classify_remote_artifact_url("https://downloads.acme.example/server.der") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/chain.p7b?dl=1") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/bundle.p7c") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/signed.p7m") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/signed.p7s") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/cert.pkcs7") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/signing.spc") == "document"
    assert _classify_remote_artifact_url("https://downloads.acme.example/revoked.crl") == "document"


def test_classify_remote_artifact_url_recognizes_dump_binary_artifacts() -> None:
    assert _classify_remote_artifact_url("https://cache.acme.example/redis/dump.rdb") == "document"
    assert _classify_remote_artifact_url("https://cache.acme.example/redis/appendonly.aof?dl=1") == "document"
    assert _classify_remote_artifact_url("https://db.acme.example/level/000123.ldb") == "document"
    assert _classify_remote_artifact_url("https://db.acme.example/rocks/000124.sst?download=1") == "document"
    assert _classify_remote_artifact_url("https://db.acme.example/lmdb/data.mdb") == "document"
    assert _classify_remote_artifact_url("https://jvm.acme.example/prod.hprof") == "document"
    assert _classify_remote_artifact_url("https://jvm.acme.example/recording.jfr") == "document"
    assert _classify_remote_artifact_url("https://crash.acme.example/process.dmp") == "document"
    assert _classify_remote_artifact_url("https://chrome.acme.example/profile.cpuprofile") == "config"
    assert _classify_remote_artifact_url("https://chrome.acme.example/snapshot.heapsnapshot") == "config"
    assert _classify_remote_artifact_url("https://diag.acme.example/node.heapdump") == "document"
    assert _classify_remote_artifact_url("https://diag.acme.example/node.heapprofile") == "document"
    assert _classify_remote_artifact_url("https://diag.acme.example/cpu.pprof") == "document"
    assert _classify_remote_artifact_url("https://diag.acme.example/profile.prof") == "document"
    assert _classify_remote_artifact_url("https://diag.acme.example/memory.memprof") == "document"


def test_classify_remote_artifact_url_recognizes_browser_profile_artifacts() -> None:
    assert _classify_remote_artifact_url("https://profile.acme.example/Default/History") == "document"
    assert _classify_remote_artifact_url("https://profile.acme.example/Default/Archived%20History") == "document"
    assert _classify_remote_artifact_url("https://profile.acme.example/Default/Favicons") == "document"
    assert _classify_remote_artifact_url("https://profile.acme.example/Default/Top%20Sites") == "document"
    assert _classify_remote_artifact_url("https://profile.acme.example/Default/Bookmarks") == "config"
    assert _classify_remote_artifact_url("https://profile.acme.example/Default/Bookmarks.bak") == "config"
    assert _classify_remote_artifact_url("https://profile.acme.example/Default/Preferences") == "config"
    assert _classify_remote_artifact_url("https://profile.acme.example/Default/Secure%20Preferences") == "config"
    assert _classify_remote_artifact_url("https://profile.acme.example/Default/Network%20Persistent%20State") == "config"
    assert _classify_remote_artifact_url("https://profile.acme.example/Default/WebCacheV01.dat") == "document"
    assert _suffix_from_content_type("application/vnd.sqlite3") == ".sqlite"
    assert _suffix_from_content_type("application/x-sqlite3") == ".sqlite"
    assert _suffix_from_content_type("application/vnd.ms-ese") == ".dat"
    assert _extract_artifact_relative_route_urls(
        'window.cache = "downloads/WebCacheV01.dat";',
        base_url="https://profile.acme.example/app.js",
    ) == ["https://profile.acme.example/downloads/WebCacheV01.dat"]


def test_classify_remote_artifact_url_recognizes_gitmodules_configs() -> None:
    assert _classify_remote_artifact_url("https://repo.acme.example/.gitmodules?raw=1") == "config"
    assert _classify_remote_artifact_url("https://repo.acme.example/project/.gitmodules") == "config"
    assert _classify_remote_artifact_url("https://repo.acme.example/.gitreview?raw=1") == "config"


def test_classify_remote_artifact_url_recognizes_oauth_well_known_metadata() -> None:
    assert (
        _classify_remote_artifact_url(
            "https://login.acme.example/.well-known/oauth-authorization-server"
        )
        == "config"
    )
    assert (
        _classify_remote_artifact_url(
            "https://api.acme.example/.well-known/oauth-protected-resource"
        )
        == "config"
    )
    assert (
        _classify_remote_artifact_url("https://login.acme.example/.well-known/openid-federation")
        == "config"
    )
    assert (
        _classify_remote_artifact_url("https://login.acme.example/.well-known/uma2-configuration")
        == "config"
    )
    assert (
        _classify_remote_artifact_url("https://login.acme.example/.well-known/jwks.json")
        == "config"
    )
    assert (
        _classify_remote_artifact_url(
            "https://identity.acme.example/.well-known/related-website-set.json"
        )
        == "config"
    )
    assert (
        _classify_remote_artifact_url(
            "https://identity.acme.example/.well-known/first-party-set.json"
        )
        == "config"
    )


def test_classify_remote_artifact_url_recognizes_model_binary_artifacts() -> None:
    assert _classify_remote_artifact_url("https://models.acme.example/keras-model.keras") == "archive"
    assert _classify_remote_artifact_url("https://models.acme.example/ranker.onnx") == "document"
    assert _classify_remote_artifact_url("https://models.acme.example/embed.safetensors?download=1") == "document"
    assert _classify_remote_artifact_url("https://models.acme.example/vectorizer.joblib") == "document"
    assert _classify_remote_artifact_url("https://models.acme.example/pipeline.pkl") == "document"
    assert _classify_remote_artifact_url("https://models.acme.example/checkpoint.pt") == "document"
    assert _classify_remote_artifact_url("https://models.acme.example/weights.pth") == "document"
    assert _classify_remote_artifact_url("https://models.acme.example/train.ckpt") == "document"


def test_classify_remote_artifact_url_recognizes_compiled_mobile_jvm_artifacts() -> None:
    assert _classify_remote_artifact_url("https://mobile.acme.example/classes.dex") == "document"
    assert _classify_remote_artifact_url("https://mobile.acme.example/boot.oat") == "document"
    assert _classify_remote_artifact_url("https://mobile.acme.example/boot.odex") == "document"
    assert _classify_remote_artifact_url("https://mobile.acme.example/boot.vdex?dl=1") == "document"
    assert _classify_remote_artifact_url("https://jvm.acme.example/MainActivity.class") == "document"


def test_compiled_mobile_jvm_content_types_map_to_static_artifact_suffixes() -> None:
    assert _suffix_from_content_type("application/x-dex") == ".dex"
    assert _suffix_from_content_type("application/vnd.android.dex") == ".dex"
    assert _suffix_from_content_type("application/x-android-dex") == ".dex"
    assert _suffix_from_content_type("application/java-vm") == ".class"
    assert _suffix_from_content_type("application/x-java-class") == ".class"
    assert _suffix_from_content_type("application/x-cpio") == ".cpio"
    assert _suffix_from_content_type("application/x-oat") == ".oat"
    assert _suffix_from_content_type("application/x-odex") == ".odex"
    assert _suffix_from_content_type("application/x-vdex; charset=binary") == ".vdex"


def test_keystore_content_types_map_to_static_artifact_suffixes() -> None:
    assert _suffix_from_content_type("application/x-java-keystore") == ".jks"
    assert _suffix_from_content_type("application/x-java-jce-keystore") == ".jceks"
    assert _suffix_from_content_type("application/x-bouncycastle-keystore") == ".bks"
    assert _suffix_from_content_type("application/pkcs12") == ".p12"
    assert _suffix_from_content_type("application/x-pkcs12") == ".p12"
    assert _suffix_from_content_type("application/x-pkcs12-certificates; charset=binary") == ".p12"


def test_certificate_content_types_map_to_static_artifact_suffixes() -> None:
    assert _suffix_from_content_type("application/pkix-cert") == ".der"
    assert _suffix_from_content_type("application/x-x509-ca-cert") == ".der"
    assert _suffix_from_content_type("application/x-x509-user-cert") == ".der"
    assert _suffix_from_content_type("application/pkix-crl") == ".crl"
    assert _suffix_from_content_type("application/x-pkcs7-crl") == ".crl"
    assert _suffix_from_content_type("application/pkcs7-mime") == ".p7m"
    assert _suffix_from_content_type("application/x-pkcs7-certificates") == ".p7b"
    assert _suffix_from_content_type("application/pkcs7-signature; charset=binary") == ".p7s"
    assert _suffix_from_content_type("application/x-pem-file") == ".pem"


def test_dump_content_types_map_to_static_artifact_suffixes() -> None:
    assert _suffix_from_content_type("application/x-redis-rdb") == ".rdb"
    assert _suffix_from_content_type("application/x-redis-aof") == ".aof"
    assert _suffix_from_content_type("application/x-leveldb") == ".ldb"
    assert _suffix_from_content_type("application/x-rocksdb") == ".sst"
    assert _suffix_from_content_type("application/x-lmdb") == ".mdb"
    assert _suffix_from_content_type("application/x-java-hprof") == ".hprof"
    assert _suffix_from_content_type("application/jfr; charset=binary") == ".jfr"
    assert _suffix_from_content_type("application/x-minidump") == ".dmp"
    assert _suffix_from_content_type("application/vnd.chrome.cpuprofile+json") == ".cpuprofile"
    assert _suffix_from_content_type("application/vnd.chrome.heapsnapshot+json") == ".heapsnapshot"
    assert _suffix_from_content_type("application/x-heapdump") == ".heapdump"
    assert _suffix_from_content_type("application/x-heap-profile") == ".heapprofile"
    assert _suffix_from_content_type("application/x-pprof") == ".pprof"
    assert _suffix_from_content_type("application/vnd.google.pprof") == ".pprof"
    assert _suffix_from_content_type("application/x-memory-profile") == ".memprof"


def test_calendar_and_vcard_content_types_map_to_static_artifact_suffixes() -> None:
    assert _suffix_from_content_type("text/calendar; charset=utf-8") == ".ics"
    assert _suffix_from_content_type("text/x-vcalendar") == ".ics"
    assert _suffix_from_content_type("application/ics") == ".ics"
    assert _suffix_from_content_type("text/vcard") == ".vcf"
    assert _suffix_from_content_type("text/x-vcard") == ".vcf"
    assert _suffix_from_content_type("text/directory") == ".vcf"
    assert _classify_remote_artifact_url("https://downloads.acme.example/team.vcard?dl=1") == "config"
