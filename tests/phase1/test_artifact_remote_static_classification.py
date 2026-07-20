from __future__ import annotations

from forge.engagement_orchestrator import (
    _classify_remote_artifact_candidate,
    _classify_remote_artifact_url,
    _extract_artifact_relative_route_urls,
    _suffix_from_content_type,
)


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
