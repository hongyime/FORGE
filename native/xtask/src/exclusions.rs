pub fn reason(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if lower == "archive/ghunt-companion-extension"
        || lower.starts_with("archive/ghunt-companion-extension/")
    {
        return Some("archived_external_runtime_bundle");
    }
    let source_root = [
        "forge/",
        "tests/",
        "rust_core/",
        "native/",
        "scripts/",
        "tools/",
        "alembic/",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix));
    let filename = lower.rsplit('/').next().unwrap_or("");
    let code = [
        ".py", ".pyi", ".rs", ".js", ".jsx", ".ts", ".tsx", ".ps1", ".sh",
    ]
    .iter()
    .any(|ext| filename.ends_with(ext));
    for part in lower.split('/') {
        let sensitive_directory = ["credentials", "secrets", "keys"].contains(&part);
        if part.starts_with(".env")
            || [".key", ".pem", ".pfx", ".p12", ".jks"]
                .iter()
                .any(|ext| part.ends_with(ext))
            || ["credentials.json", "auth.json", "id_rsa", "id_ed25519"].contains(&part)
            || (sensitive_directory && (!source_root || (!code && filename.contains('.'))))
        {
            return Some("secret_or_environment");
        }
        if [
            "vendor",
            "node_modules",
            ".venv",
            "venv",
            "dist",
            "build",
            "target",
            "downloads",
            "obfuscated",
        ]
        .contains(&part)
            || part.starts_with("pyarmor_runtime")
            || part.ends_with(".egg-info")
            || [
                "package-lock.json",
                "pnpm-lock.yaml",
                "yarn.lock",
                "cargo.lock",
            ]
            .contains(&part)
        {
            return Some("vendor_or_runtime");
        }
        if [
            "cache",
            ".cache",
            "__pycache__",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            "logs",
            ".git",
            ".benchmarks",
            ".hypothesis",
            "data",
            ".forge_data",
            "reports",
            "imports",
        ]
        .contains(&part)
            || part.ends_with("_logs")
            || part.ends_with("_raw_response.md")
            || part.starts_with(".tmp")
            || (!source_root && ["sessions", "transcripts"].contains(&part))
            || [
                ".db",
                ".sqlite",
                ".sqlite3",
                ".log",
                ".jsonl",
                ".db-wal",
                ".db-shm",
                ".sqlite-wal",
                ".sqlite-shm",
            ]
            .iter()
            .any(|ext| part.ends_with(ext))
        {
            return Some("database_log_cache_or_private_runtime");
        }
    }
    None
}
