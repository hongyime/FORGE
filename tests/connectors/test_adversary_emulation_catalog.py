"""Tests for the Muraena/Necrobrowser catalog entries.

Backlog item: Do Next #19 — Muraena + Necrobrowser catalog entries.

Under the v2 scoped-exploitation contract, Muraena (reverse-proxy
phishing framework) and Necrobrowser (post-login browser automation
framework) are INTEGRATION TARGETS, not catalog-only unsafe-text. Wave 1
ships them as catalog entries with ``integration_planned`` status so
operators can see them, see the gates that will govern them, and run
``forge connectors policy-summary --json`` to confirm they are not
runnable yet.

These tests pin the invariants that must survive the Wave 2 / Wave 3
integration work:

* They appear in both the connector catalog (``forge connectors list``)
  AND the provider policy summary (``forge connectors policy-summary``).
* ``execution_status`` is ``planned_fail_closed`` — not runnable.
* ``implementation_status`` is ``integration_planned`` — explicit about
  why.
* Their required scope-manifest permissions are declared and visible.
* The provider policy summary surfaces a dedicated
  ``integration_planned_provider_ids`` field so operators can audit it.
"""

from __future__ import annotations

from forge.connectors.registry import connector_statuses, connector_summary
from forge.utils.intel.observations import provider_catalog_policy_summary


class TestConnectorCatalogEntries:
    """Entries must appear in ``forge connectors list`` output."""

    def test_muraena_proxy_is_registered_as_integration_planned(self) -> None:
        rows = connector_statuses(env={}, which=lambda _n: None, include_paid=True)
        by_id = {row["id"]: row for row in rows}
        muraena = by_id.get("muraena_proxy")
        assert muraena is not None, "muraena_proxy missing from connector catalog"
        assert muraena["domain"] == "active_validation"
        assert muraena["cost_profile"] == "free_local"
        assert muraena["safety"] == "active_validation_gated"
        assert muraena["implementation_status"] == "integration_planned"
        assert muraena["execution_status"] == "planned_fail_closed"
        assert muraena["runner_supported"] is False
        # Scope-manifest permission gates that must hold before any
        # future integration execution path lands.
        for gate in (
            "approval",
            "roe_id",
            "scope_manifest",
            "reverse_proxy_permission",
            "live_gate",
        ):
            assert gate in muraena["required_gates"], gate

    def test_necrobrowser_automation_is_registered_as_integration_planned(self) -> None:
        rows = connector_statuses(env={}, which=lambda _n: None, include_paid=True)
        by_id = {row["id"]: row for row in rows}
        necro = by_id.get("necrobrowser_automation")
        assert necro is not None, "necrobrowser_automation missing from connector catalog"
        assert necro["domain"] == "active_validation"
        assert necro["cost_profile"] == "free_local"
        assert necro["safety"] == "active_validation_gated"
        assert necro["implementation_status"] == "integration_planned"
        assert necro["execution_status"] == "planned_fail_closed"
        assert necro["runner_supported"] is False
        for gate in (
            "approval",
            "roe_id",
            "scope_manifest",
            "post_login_automation_permission",
            "live_gate",
        ):
            assert gate in necro["required_gates"], gate

    def test_both_entries_count_as_planned_fail_closed_in_summary(self) -> None:
        rows = connector_statuses(env={}, which=lambda _n: None, include_paid=True)
        summary = connector_summary(rows)
        # active_validation_plugins + muraena_proxy + necrobrowser_automation
        assert summary["planned_fail_closed_count"] >= 3


class TestProviderPolicySummary:
    """Entries must appear in ``forge connectors policy-summary --json``."""

    def test_integration_planned_provider_ids_lists_both_entries(self) -> None:
        summary = provider_catalog_policy_summary()
        assert "integration_planned_provider_ids" in summary
        ids = summary["integration_planned_provider_ids"]
        assert ids == ["muraena_proxy", "necrobrowser_automation"]

    def test_integration_planned_collection_method_is_counted(self) -> None:
        summary = provider_catalog_policy_summary()
        counts = summary["collection_method_counts"]
        assert counts.get("integration_planned", 0) == 2

    def test_integration_planned_safety_tier_is_counted(self) -> None:
        summary = provider_catalog_policy_summary()
        counts = summary["safety_tier_counts"]
        assert counts.get("integration_planned_offensive", 0) == 2

    def test_integration_planned_entries_are_not_counted_as_live_or_api(self) -> None:
        """Backlog #19 contract: Muraena/Necro are not operational providers."""
        summary = provider_catalog_policy_summary()
        live_ids = set(summary["live_or_api_provider_ids"])
        assert "muraena_proxy" not in live_ids
        assert "necrobrowser_automation" not in live_ids

    def test_integration_planned_entries_are_operator_opt_in_gated(self) -> None:
        summary = provider_catalog_policy_summary()
        gated = set(summary["manual_opt_in_provider_ids"])
        assert "muraena_proxy" in gated
        assert "necrobrowser_automation" in gated

    def test_adversary_emulation_category_is_registered(self) -> None:
        summary = provider_catalog_policy_summary()
        counts = summary["category_counts"]
        assert counts.get("adversary_emulation", 0) == 2

    def test_summary_total_count_includes_new_entries(self) -> None:
        summary = provider_catalog_policy_summary()
        # 48 baseline entries + 2 new = 50.
        assert summary["total_count"] == 50
