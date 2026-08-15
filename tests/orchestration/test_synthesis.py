from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.orchestration.synthesis import (
    SeedCandidate,
    SynthesisSummary,
    artifact_seed_candidates_from_row,
    coerce_social_profile_urlish_candidate,
    email_seed_candidates_from_row,
    host_seed_candidates_from_row,
    insert_seed_relation,
    lookup_seed_depth,
    merge_seed_metadata,
    normalize_social_profile_anchor,
    preferred_seed_source,
    scope_seed_candidate,
    seed_lookup_keys,
    social_profile_account_handle_candidates,
    social_profile_anchor_seed_candidate,
    social_profile_candidate_batch_entries,
    social_profile_candidate_dedupe_family_entries,
    social_profile_candidate_family_entries,
    social_profile_direct_platform,
    social_profile_domain_alias_text,
    social_profile_domain_host_candidates,
    social_profile_domain_host_key_candidates,
    social_profile_domain_host_string_candidates,
    social_profile_domain_host_value_candidates,
    social_profile_domain_hosts,
    social_profile_identity_url_hint_values,
    social_profile_payload_candidate_items,
    social_profile_payload_candidate_items_at_depth,
    social_profile_payload_child_candidate_items,
    social_profile_payload_child_context,
    social_profile_payload_dedupe_key,
    social_profile_payload_entries,
    social_profile_payload_entry,
    social_profile_payload_has_profile_hint,
    social_profile_payload_with_inherited_context,
    social_profile_handle_pivot_entry,
    social_profile_handles,
    social_profile_host_pivot_entry,
    social_profile_link_handle_candidates,
    social_profile_platform_hint,
    social_profile_platform_hint_candidate,
    social_profile_platform_label_candidate,
    social_profile_pivot_family,
    social_profile_pivots,
    social_profile_pivot_batch_entries,
    social_profile_pivot_family_entries,
    social_profile_profile_candidates_from_pivots,
    social_profile_related_host_batch_entries,
    social_profile_related_host_family_entries,
    social_profile_related_host_group_entries,
    social_profile_related_hosts,
    social_profile_scalar_url_hint_value_for_item_key,
    social_profile_scalar_url_hint_values,
    social_profile_seed_pivot_entry,
    social_profile_text_handle_candidates,
    social_profile_url_hint_value_for_item_key,
    social_profile_url_hint_values,
    social_profile_url_pivot_entry,
    social_profile_value_batch_entries,
    social_profile_value_entry,
    social_profile_value_family_entries,
    social_profile_value_group_entries,
    should_promote_bluesky_domain_handle,
    synthesis_summary_log_message,
    upsert_seed_candidate,
)


def _bootstrap(db_path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
        """
    )
    con.commit()
    return con


def test_synthesis_contracts_remain_legacy_import_compatible() -> None:
    from forge.engagement_orchestrator import (  # noqa: PLC0415
        SeedCandidate as LegacySeedCandidate,
        SynthesisSummary as LegacySynthesisSummary,
    )

    assert LegacySeedCandidate is SeedCandidate
    assert LegacySynthesisSummary is SynthesisSummary


def test_synthesis_summary_log_message_matches_cli_shapes() -> None:
    assert synthesis_summary_log_message(None) is None
    assert synthesis_summary_log_message(SynthesisSummary(root_domains=["acme.example"])) is None
    summary = SynthesisSummary(
        seeds_inserted=2,
        relations_inserted=1,
        corroborated_count=3,
        root_domains=["acme.example", "beta.example"],
    )

    assert synthesis_summary_log_message(summary) == (
        "seeds+=2 relations+=1 corroborated=3"
    )
    assert synthesis_summary_log_message(summary, include_roots=True) == (
        "seeds+=2 relations+=1 roots=2"
    )


def test_synthesis_summary_log_message_is_exported_from_orchestration_package() -> None:
    from forge import orchestration as orchestration_package  # noqa: PLC0415

    assert orchestration_package.synthesis_summary_log_message is synthesis_summary_log_message


def test_seed_source_and_metadata_policy_helpers() -> None:
    assert preferred_seed_source("scope", "artifact") == "scope"
    assert preferred_seed_source("discovered", "operator") == "operator"
    assert preferred_seed_source("", "cross_reference") == "cross_reference"
    assert merge_seed_metadata({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}
    assert merge_seed_metadata("not-json", {"b": 2}) == {"b": 2}


def _classify_seed_value_for_test(value: str) -> str:
    if "@" in value:
        return "email"
    if value.count(".") == 3 and all(part.isdigit() for part in value.split(".")):
        return "ipv4"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    normalized = value[2:] if value.startswith("*.") else value
    if "." in normalized:
        return "subdomain" if normalized.count(".") > 1 else "domain"
    return "unknown"


def _normalize_root_domain_for_test(hostname: str) -> str:
    labels = str(hostname or "").strip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else str(hostname or "").strip(".").lower()


def _normalize_phone_seed_value_for_test(value: str) -> str:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    return f"+1{digits[-10:]}" if len(digits) >= 10 else f"+{digits}"


def _run_ordered_batch_for_test(batch_items, worker, *, default_factory):  # noqa: ANN001
    results = []
    for item in batch_items:
        try:
            results.append(worker(item))
        except Exception:  # noqa: BLE001
            results.append(default_factory())
    return results


def test_candidate_builder_helpers_derive_scope_email_host_and_artifact_seeds() -> None:
    scope_candidate = scope_seed_candidate(
        "*.acme.example",
        classify_seed_value=_classify_seed_value_for_test,
    )
    email_candidates = email_seed_candidates_from_row(
        {"email": "Security@mail.Acme.Example"},
        {("email", "security@mail.acme.example"): 2},
        {"acme.example"},
        depth_limit=3,
        normalize_root_domain=_normalize_root_domain_for_test,
    )
    host_candidates = host_seed_candidates_from_row(
        {"ip": "203.0.113.10", "hostname": "api.acme.example"},
        {("subdomain", "api.acme.example"): 2},
        classify_seed_value=_classify_seed_value_for_test,
        normalize_root_domain=_normalize_root_domain_for_test,
        is_placeholder_host_ip=lambda _value: False,
        depth_limit=3,
    )
    artifact_candidates = artifact_seed_candidates_from_row(
        {
            "source_url": "https://cdn.acme.example/releases/app.apk",
            "local_path": "",
            "artifact_type": "apk",
        },
        {},
        normalize_root_domain=_normalize_root_domain_for_test,
        is_mobile_bundle_url=lambda value: value.endswith(".apk"),
        is_mobile_bundle_path=lambda value: str(value).endswith(".apk"),
        is_social_platform_host=lambda _hostname: False,
        is_managed_cloud_provider_host=lambda _hostname: False,
        depth_limit=3,
    )

    assert scope_candidate == SeedCandidate(
        seed_value="acme.example",
        seed_type="domain",
        source="scope",
        depth=0,
        confidence=1.0,
    )
    assert [(item.seed_type, item.seed_value, item.depth) for item in email_candidates] == [
        ("email", "security@mail.acme.example", 2),
        ("username", "security", 3),
        ("domain", "mail.acme.example", 3),
    ]
    assert [(item.seed_type, item.seed_value, item.depth, item.parent_value) for item in host_candidates] == [
        ("ipv4", "203.0.113.10", 2, "api.acme.example"),
        ("subdomain", "api.acme.example", 2, None),
        ("domain", "acme.example", 3, "api.acme.example"),
    ]
    assert [(item.seed_type, item.seed_value, item.depth, item.parent_value) for item in artifact_candidates] == [
        ("apk_url", "https://cdn.acme.example/releases/app.apk", 1, None),
        ("subdomain", "cdn.acme.example", 2, "https://cdn.acme.example/releases/app.apk"),
        ("domain", "acme.example", 3, "cdn.acme.example"),
    ]


def test_social_profile_anchor_helpers_normalize_lookup_and_build_candidates() -> None:
    assert normalize_social_profile_anchor(
        "phone: (555) 000-1111",
        normalize_phone_seed_value=_normalize_phone_seed_value_for_test,
        classify_seed_value=_classify_seed_value_for_test,
    ) == ("+15550001111", "phone")
    assert normalize_social_profile_anchor(
        "email: Security@Acme.Example",
        normalize_phone_seed_value=_normalize_phone_seed_value_for_test,
        classify_seed_value=_classify_seed_value_for_test,
    ) == ("security@acme.example", "email")
    assert seed_lookup_keys("username", "@rootops") == [
        ("username", "@rootops"),
        ("username", "rootops"),
    ]
    assert lookup_seed_depth({("username", "rootops"): 2}, "username", "@rootops") == 2

    candidate = social_profile_anchor_seed_candidate(
        {"email": "phone: (555) 000-1111", "source": "phone_lookup"},
        {("phone", "+15550001111"): 3},
        normalize_phone_seed_value=_normalize_phone_seed_value_for_test,
        classify_seed_value=_classify_seed_value_for_test,
    )
    duplicate_username = social_profile_anchor_seed_candidate(
        {"email": "username:rootops", "source": "sherlock"},
        {("username", "@rootops"): 2},
        normalize_phone_seed_value=_normalize_phone_seed_value_for_test,
        classify_seed_value=_classify_seed_value_for_test,
    )
    unknown_anchor = social_profile_anchor_seed_candidate(
        {"email": "not-a-known-anchor", "source": "social"},
        {},
        normalize_phone_seed_value=_normalize_phone_seed_value_for_test,
        classify_seed_value=_classify_seed_value_for_test,
    )

    assert candidate == SeedCandidate(
        seed_value="+15550001111",
        seed_type="phone",
        source="discovered",
        depth=3,
        confidence=0.73,
        metadata={
            "rule": "social_profile_anchor",
            "source": "phone_lookup",
        },
    )
    assert duplicate_username is None
    assert unknown_anchor is None


def test_social_profile_profile_candidate_helpers_filter_flatten_and_prepare_dedupe_keys() -> None:
    candidates = social_profile_profile_candidates_from_pivots(
        [
            ("ghostops", "username", "same_entity", 0.86, {"rule": "handle"}),
            ("security@acme.example", "email", "same_entity", 0.9, {"rule": "self"}),
            ("https://portal.acme.example/login", "url", "related_asset", 0.8, {"rule": "url"}),
        ],
        anchor_value="security@acme.example",
        anchor_type="email",
        base_depth=2,
        depth_limit=3,
    )
    filtered_batch = social_profile_candidate_batch_entries((0, [candidates[0], "skip"]))
    filtered_family = social_profile_candidate_family_entries((0, [candidates[1], object()]))
    dedupe_entries = social_profile_candidate_dedupe_family_entries((0, [*candidates, object()]))

    assert candidates == [
        SeedCandidate(
            seed_value="ghostops",
            seed_type="username",
            source="cross_reference",
            depth=3,
            confidence=0.86,
            parent_value="security@acme.example",
            parent_type="email",
            relation_type="same_entity",
            metadata={"rule": "handle"},
        ),
        SeedCandidate(
            seed_value="https://portal.acme.example/login",
            seed_type="url",
            source="cross_reference",
            depth=3,
            confidence=0.8,
            parent_value="security@acme.example",
            parent_type="email",
            relation_type="related_asset",
            metadata={"rule": "url"},
        ),
    ]
    assert filtered_batch == [candidates[0]]
    assert filtered_family == [candidates[1]]
    assert [entry[0] for entry in dedupe_entries] == [
        ("username", "ghostops", "email", "security@acme.example"),
        ("url", "https://portal.acme.example/login", "email", "security@acme.example"),
    ]


def test_social_profile_pivot_helpers_filter_and_build_standard_entries() -> None:
    url_pivot = social_profile_url_pivot_entry(
        ("https://portal.acme.example/login", "github", 0.74, "epieos"),
        classify_seed_value=_classify_seed_value_for_test,
    )
    host_pivot = social_profile_host_pivot_entry(
        ("portal.acme.example", "subdomain", "github", 0.74, "epieos"),
    )
    seed_pivot = social_profile_seed_pivot_entry(
        ("ops@acme.example", "email", "same_entity", 0.77, "social_profile_email", "github", "epieos"),
    )
    handle_pivot = social_profile_handle_pivot_entry(
        ("ghostops", "github", 0.79, "epieos"),
        handle_allowed_for_platform=lambda platform, handle: platform == "github" and handle != "blocked",
    )
    blocked_handle_pivot = social_profile_handle_pivot_entry(
        ("blocked", "github", 0.79, "epieos"),
        handle_allowed_for_platform=lambda _platform, _handle: False,
    )
    invalid_url_pivot = social_profile_url_pivot_entry(
        ("mailto:ops@acme.example", "github", 0.74, "epieos"),
        classify_seed_value=_classify_seed_value_for_test,
    )
    batch_entries = social_profile_pivot_batch_entries((0, [url_pivot, "skip", ("bad",)]))
    family_entries = social_profile_pivot_family_entries((0, [host_pivot, object(), seed_pivot, handle_pivot]))

    assert url_pivot == (
        "https://portal.acme.example/login",
        "url",
        "related_asset",
        0.72,
        {"rule": "social_profile_url", "platform": "github", "source": "epieos"},
    )
    assert host_pivot == (
        "portal.acme.example",
        "subdomain",
        "related_asset",
        0.73,
        {"rule": "social_profile_host", "platform": "github", "source": "epieos"},
    )
    assert seed_pivot == (
        "ops@acme.example",
        "email",
        "same_entity",
        0.77,
        {"rule": "social_profile_email", "platform": "github", "source": "epieos"},
    )
    assert handle_pivot == (
        "ghostops",
        "username",
        "same_entity",
        0.81,
        {"rule": "social_profile_handle", "platform": "github", "source": "epieos"},
    )
    assert blocked_handle_pivot is None
    assert invalid_url_pivot is None
    assert batch_entries == [url_pivot]
    assert family_entries == [host_pivot, seed_pivot, handle_pivot]


def test_social_profile_pivots_dispatches_families_and_filters_invalid_entries() -> None:
    def _pivot_family(family: str, **_kwargs) -> list[object]:
        return {
            "urls": [
                (
                    "https://portal.acme.example/login",
                    "url",
                    "related_asset",
                    0.72,
                    {"family": family},
                ),
                "skip-me",
            ],
            "hosts": [
                (
                    "portal.acme.example",
                    "subdomain",
                    "related_asset",
                    0.73,
                    {"family": family},
                )
            ],
        }[family]

    pivots = social_profile_pivots(
        {},
        source_label="epieos",
        platform="github",
        base_confidence=0.74,
        company_profile=False,
        pivot_families=("urls", "hosts"),
        pivot_family=_pivot_family,
        pivot_batch_entries=social_profile_pivot_batch_entries,
        pivot_family_entries=social_profile_pivot_family_entries,
        run_ordered_batch=_run_ordered_batch_for_test,
    )

    assert [pivot[:3] for pivot in pivots] == [
        ("https://portal.acme.example/login", "url", "related_asset"),
        ("portal.acme.example", "subdomain", "related_asset"),
    ]


def test_social_profile_pivot_family_builds_platform_specific_entries() -> None:
    def _handles(_profile: dict[str, object], *, platform: str = "") -> list[str]:
        del platform
        return ["acme.example"]

    def _empty_values(_profile: dict[str, object]) -> list[str]:
        return []

    def _empty_hosts(_profile: dict[str, object]) -> list[tuple[str, str]]:
        return []

    def _company_name(
        _profile: dict[str, object],
        *,
        source_label: str,
        platform: str,
    ) -> str:
        del source_label, platform
        return ""

    def _platform_profile_hosts(
        _profile: dict[str, object],
        *,
        platform: str,
    ) -> set[str]:
        del platform
        return set()

    def _matrix_hosts(_profile: dict[str, object]) -> list[tuple[str, str]]:
        return [("matrix.acme.example", "subdomain")]

    def _federated_hosts(
        _profile: dict[str, object],
        *,
        platform: str,
    ) -> list[tuple[str, str]]:
        del platform
        return [("social.acme.example", "subdomain")]

    def _domain_hosts(_profile: dict[str, object]) -> list[tuple[str, str]]:
        return [("docs.acme.example", "subdomain")]

    def _family(family: str, platform: str) -> list[tuple[str, str, str, float, dict[str, object]]]:
        return social_profile_pivot_family(
            family,
            profile={"verified_domain": True},
            source_label="artifact_social_url_extract",
            platform=platform,
            base_confidence=0.74,
            company_profile=False,
            handles=_handles,
            company_name=_company_name,
            name=lambda _profile: "",
            emails=_empty_values,
            phones=_empty_values,
            urls=_empty_values,
            platform_profile_hosts=_platform_profile_hosts,
            related_hosts=_empty_hosts,
            matrix_homeserver_hosts=_matrix_hosts,
            platform_is_federated=lambda value: value == "mastodon",
            federated_instance_hosts=_federated_hosts,
            domain_hosts=_domain_hosts,
            should_promote_bluesky_domain_handle=should_promote_bluesky_domain_handle,
            classify_seed_value=_classify_seed_value_for_test,
            handle_pivot_entry=social_profile_handle_pivot_entry,
            url_pivot_entry=lambda entry: social_profile_url_pivot_entry(
                entry,
                classify_seed_value=_classify_seed_value_for_test,
            ),
            host_pivot_entry=social_profile_host_pivot_entry,
            seed_pivot_entry=social_profile_seed_pivot_entry,
            run_ordered_batch=_run_ordered_batch_for_test,
        )

    domain_pivots = _family("domain", "bluesky")
    matrix_pivots = _family("matrix_hosts", "matrix")
    federated_pivots = _family("federated_hosts", "mastodon")

    assert [
        (seed_value, seed_type, metadata["rule"])
        for seed_value, seed_type, _relation, _confidence, metadata in domain_pivots
    ] == [
        ("docs.acme.example", "subdomain", "social_profile_domain"),
        ("acme.example", "domain", "social_profile_domain_handle"),
    ]
    assert matrix_pivots == [
        (
            "matrix.acme.example",
            "subdomain",
            "related_asset",
            0.73,
            {
                "rule": "social_profile_matrix_homeserver",
                "platform": "matrix",
                "source": "artifact_social_url_extract",
            },
        )
    ]
    assert federated_pivots == [
        (
            "social.acme.example",
            "subdomain",
            "related_asset",
            0.73,
            {
                "rule": "social_profile_federated_instance",
                "platform": "mastodon",
                "source": "artifact_social_url_extract",
            },
        )
    ]
    assert not should_promote_bluesky_domain_handle(
        {},
        "weak.example",
        source_label="name_search",
    )


def test_social_profile_platform_and_url_hint_helpers_collect_in_order() -> None:
    platform_alias_keys = ("platform", "network")
    url_hint_keys = ("profile_url", "profileUrl", "website")
    identity_url_hint_keys = ("profile_url", "profileUrl")

    def _platform_hint_candidate(value: object) -> str:
        text = str(value or "")
        if "github.com" in text:
            return "github"
        if "mastodon.social" in text:
            return "mastodon"
        return ""

    def _platform_label_candidate(value: object) -> str:
        return social_profile_platform_label_candidate(
            value,
            platform_hint_candidate=_platform_hint_candidate,
            is_social_platform_host=lambda host: host == "github.com",
            platform_label_aliases={"x_twitter": "twitter"},
        )

    profile = {
        "platform": "",
        "network": "X Twitter",
        "profile_url": "https://unknown.example/acme",
        "profileUrl": "https://github.com/acme",
        "website": {"href": "https://acme.example"},
    }

    assert social_profile_url_hint_value_for_item_key((profile, "profile_url")) == "https://unknown.example/acme"
    assert social_profile_url_hint_value_for_item_key(("not-dict", "profile_url")) is None
    assert social_profile_scalar_url_hint_value_for_item_key((profile, "website")) is None
    assert social_profile_direct_platform(
        profile,
        platform_alias_keys=platform_alias_keys,
        platform_label_candidate=_platform_label_candidate,
        run_ordered_batch=_run_ordered_batch_for_test,
    ) == "twitter"
    assert social_profile_url_hint_values(
        profile,
        url_hint_keys=url_hint_keys,
        value_for_item_key=social_profile_url_hint_value_for_item_key,
        run_ordered_batch=_run_ordered_batch_for_test,
    ) == [
        "https://unknown.example/acme",
        "https://github.com/acme",
        {"href": "https://acme.example"},
    ]
    assert social_profile_scalar_url_hint_values(
        profile,
        url_hint_keys=url_hint_keys,
        scalar_value_for_item_key=social_profile_scalar_url_hint_value_for_item_key,
        run_ordered_batch=_run_ordered_batch_for_test,
    ) == [
        "https://unknown.example/acme",
        "https://github.com/acme",
    ]
    assert social_profile_identity_url_hint_values(
        profile,
        identity_url_hint_keys=identity_url_hint_keys,
        value_for_item_key=social_profile_url_hint_value_for_item_key,
        run_ordered_batch=_run_ordered_batch_for_test,
    ) == [
        "https://unknown.example/acme",
        "https://github.com/acme",
    ]
    assert social_profile_platform_hint(
        {"profile_url": "https://unknown.example/acme", "profileUrl": "https://github.com/acme"},
        direct_platform=lambda _profile: "",
        url_hint_values=lambda candidate_profile: social_profile_url_hint_values(
            candidate_profile,
            url_hint_keys=url_hint_keys,
            value_for_item_key=social_profile_url_hint_value_for_item_key,
            run_ordered_batch=_run_ordered_batch_for_test,
        ),
        platform_hint_candidate=_platform_hint_candidate,
        run_ordered_batch=_run_ordered_batch_for_test,
    ) == "github"
    assert coerce_social_profile_urlish_candidate(
        "//github.com/acme",
        is_social_platform_host=lambda host: host == "github.com",
        classify_seed_value=_classify_seed_value_for_test,
    ) == "https://github.com/acme"
    assert coerce_social_profile_urlish_candidate(
        "portal.acme.example/login",
        is_social_platform_host=lambda _host: False,
        classify_seed_value=_classify_seed_value_for_test,
    ) == "https://portal.acme.example/login"


def test_social_profile_platform_hint_candidate_maps_known_hosts_and_callback_families() -> None:
    def _linkedin_app_profile_path_parts(parsed: object) -> list[str]:
        if str(getattr(parsed, "scheme", "") or "").strip().lower() != "linkedin":
            return []
        parts = [
            part
            for part in [
                str(getattr(parsed, "netloc", "") or "").strip("/"),
                *str(getattr(parsed, "path", "") or "").strip("/").split("/"),
            ]
            if part
        ]
        return parts if len(parts) >= 2 else []

    def _platform(candidate: object) -> str:
        return social_profile_platform_hint_candidate(
            candidate,
            coerce_urlish_candidate=lambda value: coerce_social_profile_urlish_candidate(
                value,
                is_social_platform_host=lambda host: host in {"github.com", "gist.github.com"},
                classify_seed_value=_classify_seed_value_for_test,
            ),
            linkedin_app_profile_path_parts=_linkedin_app_profile_path_parts,
            nostr_identity_handle_candidate=lambda value: "npub" if str(value).startswith("nostr:") else "",
            is_stack_exchange_network_host=lambda host: host == "askubuntu.com",
            is_mastodon_instance_host=lambda host: host == "mastodon.online",
        )

    assert _platform("linkedin://company/acme") == "linkedin_company"
    assert _platform("https://linkedin.com/in/alice") == "linkedin"
    assert _platform("https://gist.github.com/acme") == "github_gist"
    assert _platform("https://github.com/acme") == "github"
    assert _platform("https://npmjs.com/package/acme") == "npm"
    assert _platform("acct:alice@social.acme.example") == "activitypub"
    assert _platform("matrix:u/alice") == "matrix"
    assert _platform("nostr:npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq") == "nostr"
    assert _platform("https://askubuntu.com/users/1/alice") == "stackexchange"
    assert _platform("https://mastodon.online/@alice") == "mastodon"
    assert _platform("https://unknown.example/alice") == ""


def test_social_profile_handle_and_related_host_aggregators_preserve_order_and_dedupe() -> None:
    def _handle_candidate(value: object) -> str:
        text = str(value or "").strip()
        return f"handle:{text}" if text else ""

    def _query_id_handle_candidate(value: object) -> str:
        text = str(value or "").strip()
        return f"scholar:{text}" if text else ""

    def _handle_url_candidate(value: object, *, platform: str = "") -> str:
        del platform
        text = str(value or "").strip()
        if not text:
            return ""
        return f"url:{text.rsplit('/', 1)[-1]}"

    def _collection_entries(value: object) -> list[object]:
        return list(value) if isinstance(value, list) else []

    def _collection_entries_for_keys(profile: dict[str, object], keys: object) -> list[object]:
        entries: list[object] = []
        for key in keys:
            value = profile.get(str(key))
            if isinstance(value, list):
                entries.extend(value)
        return entries

    def _embedded_container_items(item: dict[str, object]) -> list[object]:
        value = item.get("children")
        return list(value) if isinstance(value, list) else []

    def _account_handle_candidate_for_item_key(item_key: tuple[dict[str, object], str]) -> str:
        item, key = item_key
        return _handle_candidate(item.get(key))

    def _link_handle_candidate_for_item_key(item_key: tuple[dict[str, object], str]) -> str:
        item, key = item_key
        return _handle_url_candidate(item.get(key))

    def _account_handle_candidates(item: object) -> list[str]:
        return social_profile_account_handle_candidates(
            item,
            handle_field_keys=("handle", "username"),
            link_entry_keys=("url", "href"),
            embedded_container_items=_embedded_container_items,
            account_handle_candidate_for_item_key=_account_handle_candidate_for_item_key,
            link_handle_candidate_for_item_key=_link_handle_candidate_for_item_key,
            handle_candidate=_handle_candidate,
            handle_url_candidate=_handle_url_candidate,
            value_entry=social_profile_value_entry,
            run_ordered_batch=_run_ordered_batch_for_test,
        )

    def _link_handle_candidates(item: object) -> list[str]:
        return social_profile_link_handle_candidates(
            item,
            link_entry_keys=("url", "href"),
            link_handle_candidate_for_item_key=_link_handle_candidate_for_item_key,
            handle_url_candidate=_handle_url_candidate,
            value_entry=social_profile_value_entry,
            run_ordered_batch=_run_ordered_batch_for_test,
        )

    def _text_handle_candidates(text: object) -> list[str]:
        return social_profile_text_handle_candidates(
            text,
            text_url_candidates=lambda _text: ["https://profiles.example/text-one", "https://profiles.example/text-one"],
            handle_url_candidate=_handle_url_candidate,
            value_entry=social_profile_value_entry,
            run_ordered_batch=_run_ordered_batch_for_test,
        )

    profile = {
        "handle": "alpha",
        "username": "bravo",
        "profile_url": "https://profiles.example/direct",
        "accounts": [
            {
                "handle": "charlie",
                "url": "https://profiles.example/account-link",
                "children": [{"username": "delta"}],
            }
        ],
        "links": [{"href": "https://profiles.example/link-one"}],
        "bio": "see link",
    }
    handles = social_profile_handles(
        profile,
        platform="github",
        handle_field_keys=("handle", "username"),
        account_list_keys=("accounts",),
        handle_link_list_keys=("links",),
        url_hint_values=lambda candidate_profile: social_profile_url_hint_values(
            candidate_profile,
            url_hint_keys=("profile_url",),
            value_for_item_key=social_profile_url_hint_value_for_item_key,
            run_ordered_batch=_run_ordered_batch_for_test,
        ),
        matrix_identity_values=lambda _profile: [],
        federated_identity_values=lambda _profile: [],
        collection_entries=_collection_entries,
        collection_entries_for_keys=_collection_entries_for_keys,
        nested_profile_dicts=lambda _profile: [],
        text_values=lambda candidate_profile: [candidate_profile.get("bio")],
        handle_candidate=_handle_candidate,
        query_id_handle_candidate=_query_id_handle_candidate,
        handle_url_candidate=_handle_url_candidate,
        matrix_user_handle_candidate=lambda _value: "",
        platform_is_federated=lambda _platform: False,
        federated_account_handle_candidate=lambda _value: "",
        account_handle_candidates=_account_handle_candidates,
        link_handle_candidates=_link_handle_candidates,
        text_handle_candidates=_text_handle_candidates,
        value_entry=social_profile_value_entry,
        value_batch_entries=social_profile_value_batch_entries,
        value_family_entries=social_profile_value_family_entries,
        value_group_entries=social_profile_value_group_entries,
        run_ordered_batch=_run_ordered_batch_for_test,
    )

    assert social_profile_value_batch_entries((0, ["one", "", "two"])) == ["one", "two"]
    assert social_profile_value_family_entries((0, ["one", "", "two"])) == ["one", "two"]
    assert social_profile_value_group_entries((0, ["one", 2, "", "two"])) == ["one", "two"]
    assert handles == [
        "handle:alpha",
        "handle:bravo",
        "url:direct",
        "handle:charlie",
        "url:account-link",
        "handle:delta",
        "url:link-one",
        "url:text-one",
    ]
    assert social_profile_related_hosts(
        {},
        urls=lambda _profile: ["https://one.example/path", "https://two.example/path"],
        related_host_candidates=lambda candidate: [
            (candidate.split("//", 1)[1].split(".", 1)[0], "subdomain"),
            ("skip",),
            ("root.example", "domain"),
        ],
        related_host_batch_entries=social_profile_related_host_batch_entries,
        related_host_family_entries=social_profile_related_host_family_entries,
        related_host_group_entries=social_profile_related_host_group_entries,
        run_ordered_batch=_run_ordered_batch_for_test,
    ) == [
        ("one", "subdomain"),
        ("root.example", "domain"),
        ("two", "subdomain"),
    ]


def test_social_profile_domain_host_helpers_extract_aliases_nested_values_and_profiles() -> None:
    domain_field_keys = ("domain", "domains", "hostname", "hostnames", "companyDomain")

    def _classify_hostname(value: str) -> str:
        return "domain" if "." in str(value or "") else "other"

    def _coerce_urlish(value: object) -> str:
        return coerce_social_profile_urlish_candidate(
            value,
            is_social_platform_host=lambda host: host == "github.com",
            classify_seed_value=_classify_hostname,
        )

    def _domain_value_candidates(value: object) -> list[tuple[str, str]]:
        return social_profile_domain_host_value_candidates(
            value,
            domain_field_keys=domain_field_keys,
            max_entries=8,
            domain_alias_text=social_profile_domain_alias_text,
            coerce_urlish_candidate=_coerce_urlish,
            classify_seed_value=_classify_hostname,
            normalize_root_domain=_normalize_root_domain_for_test,
            is_social_platform_host=lambda host: host == "github.com",
            is_managed_cloud_provider_host=lambda host: host.endswith("vercel.app"),
            run_ordered_batch=_run_ordered_batch_for_test,
        )

    def _domain_key_candidates(item_key: tuple[dict[str, object], str]) -> list[tuple[str, str]]:
        return social_profile_domain_host_key_candidates(
            item_key,
            domain_host_value_candidates=_domain_value_candidates,
        )

    def _domain_candidates(item: object) -> list[tuple[str, str]]:
        return social_profile_domain_host_candidates(
            item,
            domain_field_keys=domain_field_keys,
            domain_host_key_candidates=_domain_key_candidates,
            domain_host_value_candidates=_domain_value_candidates,
            run_ordered_batch=_run_ordered_batch_for_test,
        )

    assert social_profile_domain_alias_text("applinks:app.acme.example") == "app.acme.example"
    assert social_profile_domain_host_string_candidates(
        "*.portal.acme.example",
        domain_alias_text=social_profile_domain_alias_text,
        coerce_urlish_candidate=_coerce_urlish,
        classify_seed_value=_classify_hostname,
        normalize_root_domain=_normalize_root_domain_for_test,
        is_social_platform_host=lambda host: host == "github.com",
        is_managed_cloud_provider_host=lambda host: host.endswith("vercel.app"),
    ) == [
        ("portal.acme.example", "subdomain"),
        ("acme.example", "domain"),
    ]
    assert _domain_value_candidates(
        {
            "value": "https://proof.acme.example/.well-known/security.txt",
            "domains": [
                "status.acme.example",
                {"href": "webcredentials:auth.acme.example"},
            ],
            "companyDomain": "github.com",
        }
    ) == [
        ("proof.acme.example", "subdomain"),
        ("acme.example", "domain"),
        ("status.acme.example", "subdomain"),
        ("auth.acme.example", "subdomain"),
    ]
    assert social_profile_domain_hosts(
        {
            "domains": ["portal.acme.example"],
        },
        domain_field_keys=domain_field_keys,
        work_history_profile_entries=lambda _profile: [{"domain": "career.acme.example"}],
        nested_profile_dicts=lambda _profile: [{"hostnames": [{"hostname": "nested.acme.example"}]}],
        domain_host_key_candidates=_domain_key_candidates,
        domain_host_candidates=_domain_candidates,
        related_host_group_entries=social_profile_related_host_group_entries,
        run_ordered_batch=_run_ordered_batch_for_test,
    ) == [
        ("portal.acme.example", "subdomain"),
        ("acme.example", "domain"),
        ("career.acme.example", "subdomain"),
        ("nested.acme.example", "subdomain"),
    ]


def test_social_profile_payload_helpers_traverse_context_and_dedupe_entries() -> None:
    container_keys = ("accounts", "profiles")
    profile_hint_keys = ("handle", "profile_url")

    def _direct_platform(profile: dict[str, object]) -> str:
        return str(profile.get("platform_hint") or "")

    def _candidate_items_at_depth(
        item,
        *,
        depth: int,
        seen: set[int],
        inherited_context: dict[str, object],
    ) -> list[dict[str, object]]:
        return social_profile_payload_candidate_items_at_depth(
            item,
            depth=depth,
            seen=seen,
            inherited_context=inherited_context,
            max_entries=8,
            container_keys=container_keys,
            profile_hint_keys=profile_hint_keys,
            direct_platform=_direct_platform,
            child_candidate_items=_child_candidate_items,
            run_ordered_batch=_run_ordered_batch_for_test,
        )

    def _child_candidate_items(
        job: tuple[object, int, set[int], dict[str, object]],
    ) -> list[dict[str, object]]:
        return social_profile_payload_child_candidate_items(
            job,
            candidate_items_at_depth=_candidate_items_at_depth,
        )

    profile_data = {
        "source": "epieos",
        "platform_hint": "github",
        "accounts": [
            {"handle": "rootops"},
            {"handle": "rootops"},
            {"profile_url": "https://github.com/acme/rootops", "source": "custom"},
        ],
        "profiles": {"handle": "buildops", "platform": ""},
    }
    candidate_items = social_profile_payload_candidate_items(
        profile_data,
        candidate_items_at_depth=_candidate_items_at_depth,
    )
    entries = social_profile_payload_entries(
        profile_data,
        row_source="fallback",
        max_entries=8,
        candidate_items=lambda _payload: candidate_items,
        payload_entry=social_profile_payload_entry,
        payload_dedupe_key=social_profile_payload_dedupe_key,
        run_ordered_batch=_run_ordered_batch_for_test,
    )

    assert social_profile_payload_has_profile_hint(
        {"handle": "rootops"},
        profile_hint_keys=profile_hint_keys,
    )
    assert social_profile_payload_with_inherited_context(
        {"handle": "child"},
        {"source": "parent", "platform": "github"},
        direct_platform=_direct_platform,
    ) == {
        "handle": "child",
        "source": "parent",
        "platform": "github",
    }
    assert social_profile_payload_child_context(
        {"source": "custom", "platform_hint": "gitlab"},
        {"source": "parent"},
        direct_platform=_direct_platform,
    ) == {
        "source": "custom",
        "platform": "gitlab",
    }
    assert candidate_items == [
        {"handle": "rootops", "source": "epieos", "platform": "github"},
        {"handle": "rootops", "source": "epieos", "platform": "github"},
        {"profile_url": "https://github.com/acme/rootops", "source": "custom", "platform": "github"},
        {"handle": "buildops", "platform": "github", "source": "epieos"},
    ]
    assert entries == [
        {"handle": "rootops", "source": "epieos", "platform": "github"},
        {"profile_url": "https://github.com/acme/rootops", "source": "custom", "platform": "github"},
        {"handle": "buildops", "platform": "github", "source": "epieos"},
    ]


def test_upsert_seed_candidate_preserves_source_parent_metadata_and_email_index(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = _bootstrap(db_path)
    try:
        parent_id = upsert_seed_candidate(
            con,
            engagement_id=1001,
            candidate=SeedCandidate(
                seed_value="acme.example",
                seed_type="domain",
                source="scope",
                depth=0,
                confidence=0.95,
                metadata={"scope": True},
            ),
            depth_limit=3,
        )
        email_id = upsert_seed_candidate(
            con,
            engagement_id=1001,
            candidate=SeedCandidate(
                seed_value="Security@Acme.Example",
                seed_type="email",
                source="discovered",
                depth=2,
                confidence=0.71,
                parent_value="acme.example",
                parent_type="domain",
                metadata={"first": True},
            ),
            depth_limit=3,
        )
        same_email_id = upsert_seed_candidate(
            con,
            engagement_id=1001,
            candidate=SeedCandidate(
                seed_value="Security@Acme.Example",
                seed_type="email",
                source="operator",
                depth=1,
                confidence=0.92,
                metadata={"second": True},
            ),
            depth_limit=3,
        )
        relation_inserted = insert_seed_relation(
            con,
            engagement_id=1001,
            source_seed_id=parent_id,
            target_seed_id=email_id,
            relation_type="derived_from",
            confidence=0.71,
            metadata={"rule": "test"},
        )
        duplicate_relation_inserted = insert_seed_relation(
            con,
            engagement_id=1001,
            source_seed_id=parent_id,
            target_seed_id=email_id,
            relation_type="derived_from",
            confidence=0.71,
            metadata={"rule": "test"},
        )
        con.commit()

        seed_row = con.execute(
            """
            SELECT source, status, depth, confidence, parent_seed_id, metadata_json
            FROM engagement_seeds
            WHERE id=? AND engagement_id=1001
            """,
            (email_id,),
        ).fetchone()
        email_row = con.execute(
            """
            SELECT email, domain, source
            FROM emails
            WHERE engagement_id=1001 AND lower(email)=lower(?)
            """,
            ("Security@Acme.Example",),
        ).fetchone()
        relation_count = con.execute(
            """
            SELECT COUNT(*)
            FROM seed_relations
            WHERE engagement_id=1001 AND source_seed_id=? AND target_seed_id=?
            """,
            (parent_id, email_id),
        ).fetchone()
    finally:
        con.close()

    assert same_email_id == email_id
    assert seed_row is not None
    assert seed_row["source"] == "operator"
    assert seed_row["status"] == "pending"
    assert int(seed_row["depth"]) == 1
    assert float(seed_row["confidence"]) == 0.92
    assert int(seed_row["parent_seed_id"]) == parent_id
    assert json.loads(str(seed_row["metadata_json"])) == {
        "first": True,
        "second": True,
    }
    assert email_row is not None
    assert email_row["email"] == "security@acme.example"
    assert email_row["domain"] == "acme.example"
    assert email_row["source"] == "discovered"
    assert relation_inserted is True
    assert duplicate_relation_inserted is False
    assert relation_count is not None
    assert int(relation_count[0]) == 1
