"""
tests/integration/test_competitive_upgrades.py

Integration test harness for FORGE competitive upgrades (T0.1).

Placeholder scaffolding for the 16 competitive upgrades tracked in the
consolidated upgrade plan. Every test function is intentionally empty; each
docstring captures the exact behavior the corresponding upgrade must satisfy so
that a later implementer only has to fill in the body.

Marker convention:
  @pytest.mark.upgrade  — every test in this module (competitive upgrade suite)
  @pytest.mark.do_now   — high-priority upgrades to execute immediately
  @pytest.mark.explore  — exploratory / spike tests for research-track upgrades
  @pytest.mark.integration — inherits the standard integration gate

Fixture generators produce realistic BloodHound / AzureHound JSON structures
that mirror the on-disk export schemas SharpHound and AzureHound emit today.
They are deliberately deterministic (fixed IDs, fixed ObjectIdentifiers) so
that snapshot-style assertions remain stable across runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# ── Fixture generators ────────────────────────────────────────────────────────


def _bloodhound_meta(count: int, type_name: str) -> dict[str, Any]:
    """Return a canonical BloodHound `meta` block."""
    return {
        "methods": 0,
        "type": type_name,
        "count": count,
        "version": 5,
    }


@pytest.fixture()
def bloodhound_users_json() -> dict[str, Any]:
    """Realistic BloodHound `users.json` export (SharpHound v2 schema).

    Two users in FORGE.LOCAL. `alice` is an enabled standard user, `svc_backup`
    is a service account with SPNs (kerberoastable). Object identifiers are
    real-looking SIDs; properties mirror what SharpHound writes to disk.
    """
    return {
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-1111111111-2222222222-3333333333-1104",
                "Properties": {
                    "name": "ALICE@FORGE.LOCAL",
                    "domain": "FORGE.LOCAL",
                    "domainsid": "S-1-5-21-1111111111-2222222222-3333333333",
                    "distinguishedname": "CN=Alice,CN=Users,DC=forge,DC=local",
                    "enabled": True,
                    "pwdlastset": 1735689600,
                    "lastlogon": 1738368000,
                    "hasspn": False,
                    "unconstraineddelegation": False,
                    "trustedtoauth": False,
                    "sensitive": False,
                    "dontreqpreauth": False,
                    "admincount": False,
                },
                "PrimaryGroupSID": "S-1-5-21-1111111111-2222222222-3333333333-513",
                "Aces": [],
                "SPNTargets": [],
                "AllowedToDelegate": [],
                "HasSIDHistory": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            },
            {
                "ObjectIdentifier": "S-1-5-21-1111111111-2222222222-3333333333-1150",
                "Properties": {
                    "name": "SVC_BACKUP@FORGE.LOCAL",
                    "domain": "FORGE.LOCAL",
                    "domainsid": "S-1-5-21-1111111111-2222222222-3333333333",
                    "distinguishedname": "CN=svc_backup,OU=Services,DC=forge,DC=local",
                    "enabled": True,
                    "pwdlastset": 1704067200,
                    "lastlogon": 1738454400,
                    "hasspn": True,
                    "unconstraineddelegation": False,
                    "trustedtoauth": True,
                    "sensitive": False,
                    "dontreqpreauth": False,
                    "admincount": True,
                    "serviceprincipalnames": ["MSSQLSvc/db01.forge.local:1433"],
                },
                "PrimaryGroupSID": "S-1-5-21-1111111111-2222222222-3333333333-513",
                "Aces": [],
                "SPNTargets": [
                    {
                        "ComputerSID": "S-1-5-21-1111111111-2222222222-3333333333-1201",
                        "Port": 1433,
                        "Service": "SQLAdmin",
                    }
                ],
                "AllowedToDelegate": [],
                "HasSIDHistory": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            },
        ],
        "meta": _bloodhound_meta(2, "users"),
    }


@pytest.fixture()
def bloodhound_computers_json() -> dict[str, Any]:
    """Realistic BloodHound `computers.json` export.

    One domain controller (`DC01`) and one member server (`DB01`) in
    FORGE.LOCAL, both with resolvable LAPS metadata and empty session lists.
    """
    return {
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-1111111111-2222222222-3333333333-1000",
                "Properties": {
                    "name": "DC01.FORGE.LOCAL",
                    "domain": "FORGE.LOCAL",
                    "domainsid": "S-1-5-21-1111111111-2222222222-3333333333",
                    "distinguishedname": "CN=DC01,OU=Domain Controllers,DC=forge,DC=local",
                    "enabled": True,
                    "unconstraineddelegation": True,
                    "trustedtoauth": False,
                    "operatingsystem": "Windows Server 2022",
                    "haslaps": False,
                },
                "PrimaryGroupSID": "S-1-5-21-1111111111-2222222222-3333333333-516",
                "Sessions": {"Results": [], "Collected": True, "FailureReason": None},
                "PrivilegedSessions": {"Results": [], "Collected": True, "FailureReason": None},
                "RegistrySessions": {"Results": [], "Collected": True, "FailureReason": None},
                "LocalAdmins": {"Results": [], "Collected": True, "FailureReason": None},
                "RemoteDesktopUsers": {"Results": [], "Collected": True, "FailureReason": None},
                "DcomUsers": {"Results": [], "Collected": True, "FailureReason": None},
                "PSRemoteUsers": {"Results": [], "Collected": True, "FailureReason": None},
                "AllowedToDelegate": [],
                "AllowedToAct": [],
                "HasSIDHistory": [],
                "DumpSMSAPassword": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            },
            {
                "ObjectIdentifier": "S-1-5-21-1111111111-2222222222-3333333333-1201",
                "Properties": {
                    "name": "DB01.FORGE.LOCAL",
                    "domain": "FORGE.LOCAL",
                    "domainsid": "S-1-5-21-1111111111-2222222222-3333333333",
                    "distinguishedname": "CN=DB01,CN=Computers,DC=forge,DC=local",
                    "enabled": True,
                    "unconstraineddelegation": False,
                    "trustedtoauth": False,
                    "operatingsystem": "Windows Server 2019",
                    "haslaps": True,
                },
                "PrimaryGroupSID": "S-1-5-21-1111111111-2222222222-3333333333-515",
                "Sessions": {"Results": [], "Collected": True, "FailureReason": None},
                "PrivilegedSessions": {"Results": [], "Collected": True, "FailureReason": None},
                "RegistrySessions": {"Results": [], "Collected": True, "FailureReason": None},
                "LocalAdmins": {"Results": [], "Collected": True, "FailureReason": None},
                "RemoteDesktopUsers": {"Results": [], "Collected": True, "FailureReason": None},
                "DcomUsers": {"Results": [], "Collected": True, "FailureReason": None},
                "PSRemoteUsers": {"Results": [], "Collected": True, "FailureReason": None},
                "AllowedToDelegate": [],
                "AllowedToAct": [],
                "HasSIDHistory": [],
                "DumpSMSAPassword": [],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            },
        ],
        "meta": _bloodhound_meta(2, "computers"),
    }


@pytest.fixture()
def bloodhound_groups_json() -> dict[str, Any]:
    """Realistic BloodHound `groups.json` export with Domain Admins membership."""
    return {
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-1111111111-2222222222-3333333333-512",
                "Properties": {
                    "name": "DOMAIN ADMINS@FORGE.LOCAL",
                    "domain": "FORGE.LOCAL",
                    "domainsid": "S-1-5-21-1111111111-2222222222-3333333333",
                    "distinguishedname": "CN=Domain Admins,CN=Users,DC=forge,DC=local",
                    "admincount": True,
                    "description": "Designated administrators of the domain",
                },
                "Members": [
                    {
                        "ObjectIdentifier": (
                            "S-1-5-21-1111111111-2222222222-3333333333-1150"
                        ),
                        "ObjectType": "User",
                    }
                ],
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": True,
            }
        ],
        "meta": _bloodhound_meta(1, "groups"),
    }


@pytest.fixture()
def bloodhound_domains_json() -> dict[str, Any]:
    """Realistic BloodHound `domains.json` export."""
    return {
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-1111111111-2222222222-3333333333",
                "Properties": {
                    "name": "FORGE.LOCAL",
                    "domain": "FORGE.LOCAL",
                    "domainsid": "S-1-5-21-1111111111-2222222222-3333333333",
                    "distinguishedname": "DC=forge,DC=local",
                    "functionallevel": "2016",
                },
                "Trusts": [],
                "Links": [],
                "ChildObjects": [],
                "Aces": [],
                "GPOChanges": {
                    "LocalAdmins": [],
                    "RemoteDesktopUsers": [],
                    "DcomUsers": [],
                    "PSRemoteUsers": [],
                    "AffectedComputers": [],
                },
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        ],
        "meta": _bloodhound_meta(1, "domains"),
    }


@pytest.fixture()
def azurehound_json() -> list[dict[str, Any]]:
    """Realistic AzureHound export.

    AzureHound emits a stream of records, one JSON object per line, each with
    a `kind` discriminator (`AZTenant`, `AZUser`, `AZServicePrincipal`, ...)
    and a `data` payload matching the Microsoft Graph shape. Returned here as
    a Python list so tests can either iterate directly or dump as JSONL.
    """
    tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    return [
        {
            "kind": "AZTenant",
            "data": {
                "id": tenant_id,
                "displayName": "Forge Tenant",
                "verifiedDomains": [
                    {"name": "forgetenant.onmicrosoft.com", "isDefault": True}
                ],
            },
        },
        {
            "kind": "AZUser",
            "data": {
                "id": "11111111-2222-3333-4444-555555555555",
                "displayName": "Alice Operator",
                "userPrincipalName": "alice@forgetenant.onmicrosoft.com",
                "accountEnabled": True,
                "tenantId": tenant_id,
                "onPremisesSecurityIdentifier": (
                    "S-1-5-21-1111111111-2222222222-3333333333-1104"
                ),
            },
        },
        {
            "kind": "AZServicePrincipal",
            "data": {
                "id": "66666666-7777-8888-9999-000000000000",
                "displayName": "forge-automation",
                "appId": "cafecafe-cafe-cafe-cafe-cafecafecafe",
                "servicePrincipalType": "Application",
                "tenantId": tenant_id,
                "appOwnerOrganizationId": tenant_id,
            },
        },
        {
            "kind": "AZRoleAssignment",
            "data": {
                "id": "/providers/Microsoft.Authorization/roleAssignments/abc",
                "principalId": "66666666-7777-8888-9999-000000000000",
                "roleDefinitionId": (
                    "/providers/Microsoft.Authorization/roleDefinitions/"
                    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
                ),
                "scope": f"/tenants/{tenant_id}",
                "tenantId": tenant_id,
            },
        },
    ]


@pytest.fixture()
def bloodhound_bundle(
    tmp_path: Path,
    bloodhound_users_json: dict[str, Any],
    bloodhound_computers_json: dict[str, Any],
    bloodhound_groups_json: dict[str, Any],
    bloodhound_domains_json: dict[str, Any],
) -> Path:
    """Write the four canonical BloodHound JSON files to a temp directory."""
    bundle = tmp_path / "bloodhound"
    bundle.mkdir()
    (bundle / "users.json").write_text(json.dumps(bloodhound_users_json), encoding="utf-8")
    (bundle / "computers.json").write_text(
        json.dumps(bloodhound_computers_json), encoding="utf-8"
    )
    (bundle / "groups.json").write_text(json.dumps(bloodhound_groups_json), encoding="utf-8")
    (bundle / "domains.json").write_text(
        json.dumps(bloodhound_domains_json), encoding="utf-8"
    )
    return bundle


@pytest.fixture()
def azurehound_jsonl(tmp_path: Path, azurehound_json: list[dict[str, Any]]) -> Path:
    """Write AzureHound records as JSONL (one object per line)."""
    path = tmp_path / "azurehound.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for record in azurehound_json:
            fh.write(json.dumps(record) + "\n")
    return path


# ── Marker applied to every test in this module ───────────────────────────────

pytestmark = [pytest.mark.upgrade, pytest.mark.integration]


# ── U01: BloodHound ingest ────────────────────────────────────────────────────


@pytest.mark.do_now
def test_u01_bloodhound_users_ingest_populates_identity_graph(bloodhound_users_json):
    """U01 — Ingesting `users.json` yields identity nodes with SID + UPN preserved."""


@pytest.mark.do_now
def test_u01_bloodhound_computers_ingest_marks_domain_controllers(bloodhound_computers_json):
    """U01 — Computers flagged as DCs land in the graph with the DC role tag."""


@pytest.mark.do_now
def test_u01_bloodhound_groups_ingest_expands_membership_edges(bloodhound_groups_json):
    """U01 — Group membership entries become MemberOf edges to member SIDs."""


@pytest.mark.do_now
def test_u01_bloodhound_bundle_ingest_is_idempotent(bloodhound_bundle):
    """U01 — Re-ingesting the same bundle does not duplicate nodes or edges."""


def test_u01_bloodhound_ingest_rejects_unknown_schema_version():
    """U01 — Bundles with an unknown `meta.version` are rejected with a clear error."""


# ── U02: AzureHound ingest ────────────────────────────────────────────────────


@pytest.mark.do_now
def test_u02_azurehound_tenant_record_creates_tenant_node(azurehound_json):
    """U02 — `AZTenant` records produce a tenant node keyed by tenantId."""


@pytest.mark.do_now
def test_u02_azurehound_user_links_to_on_prem_sid(azurehound_json):
    """U02 — Users with `onPremisesSecurityIdentifier` link to the AD user node."""


@pytest.mark.do_now
def test_u02_azurehound_role_assignment_creates_privilege_edge(azurehound_json):
    """U02 — `AZRoleAssignment` records create typed privilege edges to the scope."""


def test_u02_azurehound_jsonl_streaming_ingest_bounded_memory(azurehound_jsonl):
    """U02 — Streaming JSONL ingest never buffers more than one record in memory."""


def test_u02_azurehound_service_principal_owner_org_tagged(azurehound_json):
    """U02 — Service principals record `appOwnerOrganizationId` for cross-tenant risk."""


# ── U03: Hybrid attack path (AD ↔ Entra) ──────────────────────────────────────


@pytest.mark.do_now
def test_u03_hybrid_path_from_ad_user_to_azure_role(bloodhound_bundle, azurehound_jsonl):
    """U03 — Path finder walks AD user → hybrid link → Azure role assignment."""


def test_u03_hybrid_path_ranks_shortest_privilege_chain():
    """U03 — Multiple viable chains are ranked shortest-first with tie-break on privilege."""


def test_u03_hybrid_path_respects_scope_manifest_boundaries():
    """U03 — Path finder refuses to emit edges that cross the ROE scope boundary."""


# ── U04: Kerberoast / AS-REP surface enrichment ───────────────────────────────


@pytest.mark.do_now
def test_u04_kerberoastable_users_flagged_from_spn_targets(bloodhound_users_json):
    """U04 — Users with non-empty `SPNTargets` are flagged as kerberoastable."""


def test_u04_asrep_roastable_users_flagged_from_dontreqpreauth():
    """U04 — Users with `dontreqpreauth=True` are flagged as AS-REP-roastable."""


def test_u04_kerberoast_ranking_weights_admincount_higher():
    """U04 — Kerberoastable users with `admincount=True` sort above standard users."""


# ── U05: LAPS coverage gap detector ───────────────────────────────────────────


def test_u05_laps_gap_detects_computers_without_laps(bloodhound_computers_json):
    """U05 — Computers where `haslaps=False` produce a LAPS-gap finding."""


def test_u05_laps_gap_ignores_domain_controllers():
    """U05 — DCs are excluded from LAPS-gap findings (LAPS scope is member hosts)."""


# ── U06: Unconstrained delegation surfacing ───────────────────────────────────


def test_u06_unconstrained_delegation_flagged_for_non_dc(bloodhound_computers_json):
    """U06 — Non-DC computers with `unconstraineddelegation=True` become HIGH findings."""


def test_u06_constrained_delegation_targets_reported():
    """U06 — Objects with `AllowedToDelegate` targets appear with their target set."""


# ── U07: ADCS / ESC misconfiguration checks ───────────────────────────────────


@pytest.mark.explore
def test_u07_esc1_template_with_enrollee_supplies_subject_flagged():
    """U07 — Certificate templates matching ESC1 conditions produce an ESC1 finding."""


@pytest.mark.explore
def test_u07_esc4_writable_template_acl_flagged():
    """U07 — Templates with writable ACLs by non-privileged principals report ESC4."""


# ── U08: Session hunting from BloodHound sessions ─────────────────────────────


def test_u08_active_session_edges_created_from_computer_sessions():
    """U08 — `Sessions.Results` on computers become HasSession edges to users."""


def test_u08_session_hunter_prioritises_paths_to_tier0():
    """U08 — Session hunter output ranks paths that terminate in Tier-0 assets first."""


# ── U09: OPSEC quiet-mode collection profile ──────────────────────────────────


@pytest.mark.do_now
def test_u09_opsec_quiet_collection_reduces_ldap_query_count():
    """U09 — Quiet-mode collection issues fewer LDAP queries than the default profile."""


def test_u09_opsec_quiet_collection_disables_session_enumeration():
    """U09 — Quiet mode skips computer session enumeration entirely."""


# ── U10: Owned/high-value tagging propagation ─────────────────────────────────


def test_u10_owned_tag_propagates_through_admin_edges():
    """U10 — Marking a user Owned propagates reachability to hosts they administer."""


def test_u10_high_value_tag_persists_across_reingest(bloodhound_bundle):
    """U10 — High-value tags survive re-ingestion of the same bundle."""


# ── U11: Cypher-style query API ───────────────────────────────────────────────


@pytest.mark.explore
def test_u11_query_shortest_path_between_two_sids():
    """U11 — `shortestPath(u1, u2)` returns the minimal edge sequence with edge kinds."""


@pytest.mark.explore
def test_u11_query_all_paths_to_domain_admins_bounded_by_depth():
    """U11 — Path enumeration to Domain Admins respects the configured max-depth."""


# ── U12: Exposure diff between two collections ────────────────────────────────


def test_u12_diff_detects_new_kerberoastable_user():
    """U12 — Diffing two ingests surfaces users that became kerberoastable."""


def test_u12_diff_detects_removed_dcsync_privilege():
    """U12 — DCSync ACE removed between collections shows up in the diff report."""


def test_u12_diff_output_stable_across_reruns():
    """U12 — The diff artifact is byte-stable when nothing changed between runs."""


# ── U13: Cross-forest trust walk ──────────────────────────────────────────────


@pytest.mark.explore
def test_u13_cross_forest_trust_edges_created_from_trusts_field():
    """U13 — `Trusts` on the domain object become typed TrustedBy edges to peers."""


@pytest.mark.explore
def test_u13_cross_forest_path_respects_transitive_trust_flag():
    """U13 — Non-transitive trusts are not followed by the path finder."""


# ── U14: Certificate-based hybrid pivot (PKINIT) ──────────────────────────────


@pytest.mark.explore
def test_u14_pkinit_pivot_from_azure_cert_to_ad_user():
    """U14 — A synced Entra cert linked to an AD user creates a PKINIT pivot edge."""


@pytest.mark.explore
def test_u14_pkinit_pivot_requires_upn_or_sid_binding():
    """U14 — Pivots without UPN/SID binding proof are omitted from the graph."""


# ── U15: Detection-safety scoring per finding ─────────────────────────────────


def test_u15_detection_score_reflects_edr_signal_expectations():
    """U15 — Findings score higher risk when the technique typically triggers EDR."""


def test_u15_detection_score_downweights_read_only_recon():
    """U15 — Read-only LDAP recon scores below active collection techniques."""


# ── U16: Report enrichment with attack-path narratives ────────────────────────


@pytest.mark.do_now
def test_u16_report_narrative_includes_ranked_attack_paths():
    """U16 — Phase 6 report contains the top-N ranked attack paths with edge details."""


def test_u16_report_narrative_falls_back_to_template_without_llm():
    """U16 — When no LLM is available the deterministic template still renders paths."""


def test_u16_report_narrative_redacts_credential_material():
    """U16 — Password hashes / ticket blobs never appear in the rendered narrative."""


# ── Cross-cutting harness sanity ──────────────────────────────────────────────


def test_harness_bloodhound_fixture_schema_matches_sharphound(bloodhound_bundle):
    """Sanity — Every fixture file parses as JSON with a `data` list + `meta` dict."""


def test_harness_azurehound_fixture_kinds_are_recognized(azurehound_json):
    """Sanity — Every AzureHound record carries a supported `kind` discriminator."""


def test_harness_markers_registered_in_pytest_config():
    """Sanity — `upgrade`, `do_now`, and `explore` markers are declared in pyproject."""


def test_harness_fixtures_generate_deterministic_output(
    bloodhound_users_json, azurehound_json
):
    """Sanity — Fixture output is deterministic across invocations (stable IDs)."""


# ── Additional coverage placeholders ──────────────────────────────────────────


def test_u01_bloodhound_domains_ingest_creates_domain_node(bloodhound_domains_json):
    """U01 — `domains.json` produces a domain node keyed by domain SID."""


def test_u01_bloodhound_ingest_records_audit_log_entry(bloodhound_bundle):
    """U01 — Every ingest run appends a hash-chained audit_log row."""


def test_u02_azurehound_ingest_dedupes_records_by_id(azurehound_jsonl):
    """U02 — Duplicate records with the same `data.id` collapse to one node."""


@pytest.mark.explore
def test_u07_esc8_ntlm_relay_to_web_enrollment_flagged():
    """U07 — ADCS Web Enrollment endpoints without EPA produce an ESC8 finding."""


def test_u09_opsec_quiet_collection_respects_jitter_between_queries():
    """U09 — Quiet mode inserts randomized jitter between LDAP page fetches."""


def test_u12_diff_report_includes_severity_delta():
    """U12 — Diff artifact reports severity change per finding, not just presence."""


@pytest.mark.do_now
def test_u16_report_narrative_orders_paths_by_ranked_risk():
    """U16 — Narrative section orders attack paths by combined risk score."""
