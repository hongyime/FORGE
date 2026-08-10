"""cloud_ref end-to-end integration through classifier + consumers.

Task 4 slice 2/6 — verifies that a cloud_ref seed:

* is classified by ``provider_url_seed_type`` as ``cloud_ref`` (not ``url``)
* renders through ``_safe_seed_display_value`` without garbling
* maps to a valid graph NodeType in both phase4.attack_path and the
  dashboard graph helper
* emits both URL-form and hostname-form targets from the scope-manifest
  and validation-scope routers (so scope gate matches either)
"""

from __future__ import annotations

import pytest

from forge.utils.intel.provider_urls import provider_url_seed_type


class TestProviderUrlSeedType:
    """provider_url_seed_type should agree with the orchestrator classifier."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://myapp.supabase.co/rest/v1/foo",
            "https://myapp.firebaseio.com/.json",
            "https://bucket.s3.amazonaws.com/o",
            "https://bucket.s3.us-east-1.amazonaws.com/o",
            "https://acct.blob.core.windows.net/ct/b",
            "https://myapp.vercel.app/api/health",
            "https://myapp.netlify.app/",
            "https://myapp.pages.dev/",
        ],
    )
    def test_provider_url_becomes_cloud_ref(self, url: str) -> None:
        assert provider_url_seed_type(url) == "cloud_ref"

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/path",
            "https://portal.example.com/",
        ],
    )
    def test_non_provider_url_stays_url(self, url: str) -> None:
        assert provider_url_seed_type(url) == "url"

    def test_apk_still_beats_cloud_ref(self) -> None:
        # A .apk on cloudfront should still route to apk_url (mobile bundle
        # gets priority).
        assert provider_url_seed_type("https://d123abc.cloudfront.net/build.apk") == "apk_url"


class TestSafeSeedDisplayValue:
    """Cloud refs must render safely without URL query-string cleanup breaking
    bare hostnames."""

    def test_url_form_cloud_ref_display_is_clean(self) -> None:
        from forge.phase6.report_synthesizer import ContextBuilder

        display = ContextBuilder._safe_seed_display_value(
            "https://xyz.supabase.co/rest/v1/table?apikey=SECRET",
            "cloud_ref",
        )
        assert "apikey=" not in display  # query stripped
        assert "xyz.supabase.co" in display

    def test_bare_hostname_cloud_ref_preserved(self) -> None:
        from forge.phase6.report_synthesizer import ContextBuilder

        display = ContextBuilder._safe_seed_display_value("xyz.supabase.co", "cloud_ref")
        assert display == "xyz.supabase.co"

    def test_url_cloud_ref_length_capped(self) -> None:
        from forge.phase6.report_synthesizer import ContextBuilder

        long_url = "https://xyz.supabase.co/" + "a" * 500
        display = ContextBuilder._safe_seed_display_value(long_url, "cloud_ref")
        assert len(display) <= 160


class TestGraphNodeTypeRoutesCloudRef:
    """cloud_ref must map to HOST in both graph typers (attack_path + dashboard)."""

    def test_attack_path_seed_node_type_is_host(self) -> None:
        from forge.models.attack_graph_models import NodeType
        from forge.phase4.attack_path import AttackGraphBuilder

        builder = AttackGraphBuilder.__new__(AttackGraphBuilder)
        assert builder._seed_node_type("cloud_ref") == NodeType.HOST

    def test_dashboard_seed_graph_node_type_is_host(self) -> None:
        from forge.reporting.dashboard import _seed_graph_node_type

        assert _seed_graph_node_type("cloud_ref") == "HOST"


class TestScopeManifestSeedTargets:
    """Both scope routers must emit URL + hostname targets for cloud_ref."""

    def test_cli_scope_manifest_emits_url_and_hostname(self) -> None:
        from forge.cli import _scope_manifest_seed_targets

        targets = _scope_manifest_seed_targets("https://xyz.supabase.co/rest/v1", "cloud_ref")
        assert "https://xyz.supabase.co/rest/v1" in targets
        assert "xyz.supabase.co" in targets

    def test_cli_scope_manifest_bare_hostname(self) -> None:
        from forge.cli import _scope_manifest_seed_targets

        targets = _scope_manifest_seed_targets("xyz.supabase.co", "cloud_ref")
        assert "xyz.supabase.co" in targets

    def test_cloud_validate_scope_emits_url_and_hostname(self) -> None:
        from forge.phase4.cloud_validate import _validation_scope_seed_targets

        targets = _validation_scope_seed_targets(
            "https://acct.blob.core.windows.net/ct", "cloud_ref"
        )
        assert "https://acct.blob.core.windows.net/ct" in targets
        assert "acct.blob.core.windows.net" in targets

    def test_cloud_validate_bare_hostname(self) -> None:
        from forge.phase4.cloud_validate import _validation_scope_seed_targets

        targets = _validation_scope_seed_targets("acct.blob.core.windows.net", "cloud_ref")
        assert "acct.blob.core.windows.net" in targets
