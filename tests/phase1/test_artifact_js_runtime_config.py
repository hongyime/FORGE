from __future__ import annotations

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_bun_scope_candidate_values_do_not_reuse_stale_registry_value(tmp_path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = """
registry = "registry.npmjs.org"

[install.scopes]
# comment-only line must not reuse the registry candidate
@acme = "npm.pkg.github.com/acme"
""".strip()

    assert processor._js_runtime_text_candidate_values(
        payload,
        source_label="bunfig",
    ) == [
        "registry.npmjs.org",
        "npm.pkg.github.com/acme",
    ]
