from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from typing import Any

CloudSeedRefExtractor = Callable[[str], list[tuple[str, str]]]
LiteralCloudRefParser = Callable[[str], tuple[str, str] | None]
SeedUpserter = Callable[..., None]
SeedClassifier = Callable[[str], str]
SocialHandleExtractor = Callable[[str], str | None]
SocialPlatformHint = Callable[[Mapping[str, object]], str | None]
SocialCompanyExtractor = Callable[..., str | None]
SocialNameExtractor = Callable[[Mapping[str, object]], str | None]


def lookup_engagement_seed_id(
    con: Any,
    engagement_id: int,
    seed_value: str,
    seed_type: str,
) -> int | None:
    try:
        row = con.execute(
            """
            SELECT id
            FROM engagement_seeds
            WHERE engagement_id=? AND seed_value=? AND seed_type=?
            LIMIT 1
            """,
            (engagement_id, seed_value, seed_type),
        ).fetchone()
    except Exception:  # noqa: BLE001
        return None
    if not row:
        return None
    try:
        return int(row[0])
    except (TypeError, ValueError, IndexError):
        return None


def insert_seed_relation(
    con: Any,
    engagement_id: int,
    source_seed_id: int | None,
    target_seed_id: int | None,
    *,
    relation_type: str,
    confidence: float,
    evidence: Mapping[str, object],
) -> None:
    if (
        source_seed_id is None
        or target_seed_id is None
        or source_seed_id == target_seed_id
    ):
        return
    try:
        con.execute(
            """
            INSERT OR IGNORE INTO seed_relations
                (engagement_id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                source_seed_id,
                target_seed_id,
                relation_type,
                float(confidence),
                json.dumps(dict(evidence), sort_keys=True),
            ),
        )
    except Exception:  # noqa: BLE001
        return


def promote_social_url_seed_refs(
    con: Any,
    engagement_id: int,
    seed_value: str,
    entry_type: str,
    *,
    upsert_engagement_seed: SeedUpserter,
    platform_hint: SocialPlatformHint,
    extract_handle: SocialHandleExtractor,
    extract_company_name: SocialCompanyExtractor,
    extract_profile_name: SocialNameExtractor,
    classify_seed_value: SeedClassifier,
    evidence_rule: str = "social_url_extract",
) -> None:
    profile_stub: dict[str, object] = {"profile_url": seed_value}
    platform = platform_hint(profile_stub)
    if not platform:
        return
    url_seed_id = lookup_engagement_seed_id(con, engagement_id, seed_value, entry_type)
    if url_seed_id is None:
        return

    handle = extract_handle(seed_value)
    if handle:
        upsert_engagement_seed(
            con,
            handle,
            "username",
            source="cross_reference",
            status="pending",
            depth=1,
            confidence=0.78,
        )
        username_seed_id = lookup_engagement_seed_id(con, engagement_id, handle, "username")
        insert_seed_relation(
            con,
            engagement_id,
            url_seed_id,
            username_seed_id,
            relation_type="derived_from",
            confidence=0.78,
            evidence={"rule": evidence_rule, "platform": platform},
        )

        domain_handle = str(handle or "").strip().lower()
        if platform == "bluesky" and classify_seed_value(domain_handle) == "domain":
            upsert_engagement_seed(
                con,
                domain_handle,
                "domain",
                source="cross_reference",
                status="pending",
                depth=1,
                confidence=0.82,
            )
            domain_seed_id = lookup_engagement_seed_id(
                con,
                engagement_id,
                domain_handle,
                "domain",
            )
            insert_seed_relation(
                con,
                engagement_id,
                url_seed_id,
                domain_seed_id,
                relation_type="derived_from",
                confidence=0.82,
                evidence={
                    "rule": "social_profile_domain_handle",
                    "platform": platform,
                    "source_rule": evidence_rule,
                },
            )

    company_name = extract_company_name(
        profile_stub,
        source_label="operator_seed_url",
        platform=platform,
    )
    if company_name:
        upsert_engagement_seed(
            con,
            company_name,
            "company",
            source="cross_reference",
            status="pending",
            depth=1,
            confidence=0.76,
        )
        company_seed_id = lookup_engagement_seed_id(
            con,
            engagement_id,
            company_name,
            "company",
        )
        insert_seed_relation(
            con,
            engagement_id,
            url_seed_id,
            company_seed_id,
            relation_type="derived_from",
            confidence=0.76,
            evidence={"rule": evidence_rule, "platform": platform},
        )

    full_name = extract_profile_name(profile_stub)
    if full_name:
        upsert_engagement_seed(
            con,
            full_name,
            "name",
            source="cross_reference",
            status="pending",
            depth=1,
            confidence=0.74,
        )
        name_seed_id = lookup_engagement_seed_id(con, engagement_id, full_name, "name")
        insert_seed_relation(
            con,
            engagement_id,
            url_seed_id,
            name_seed_id,
            relation_type="derived_from",
            confidence=0.74,
            evidence={"rule": evidence_rule, "platform": platform},
        )


def promote_email_localpart_seed_refs(
    con: Any,
    engagement_id: int,
    email_value: str,
    usernames: Iterable[str],
    *,
    upsert_engagement_seed: SeedUpserter,
) -> None:
    normalized_email = str(email_value or "").strip().lower()
    if not normalized_email or "@" not in normalized_email:
        return
    handles = [
        str(username or "").strip()
        for username in usernames
        if str(username or "").strip()
    ]
    if not handles:
        return

    email_seed_id = lookup_engagement_seed_id(con, engagement_id, normalized_email, "email")
    if email_seed_id is None:
        upsert_engagement_seed(
            con,
            normalized_email,
            "email",
            source="discovered",
            status="pending",
            depth=1,
            confidence=0.9,
        )
        email_seed_id = lookup_engagement_seed_id(
            con,
            engagement_id,
            normalized_email,
            "email",
        )
    if email_seed_id is None:
        return

    for handle in handles:
        username_seed_id = lookup_engagement_seed_id(con, engagement_id, handle, "username")
        if username_seed_id is None:
            upsert_engagement_seed(
                con,
                handle,
                "username",
                source="cross_reference",
                status="pending",
                depth=2,
                confidence=0.72,
            )
            username_seed_id = lookup_engagement_seed_id(
                con,
                engagement_id,
                handle,
                "username",
            )
        insert_seed_relation(
            con,
            engagement_id,
            email_seed_id,
            username_seed_id,
            relation_type="derived_from",
            confidence=0.72,
            evidence={"rule": "email_localpart_username"},
        )


def promote_cloud_asset_seed_refs(
    con: Any,
    engagement_id: int,
    seed_value: str,
    *,
    extract_cloud_asset_seed_refs: CloudSeedRefExtractor,
    parse_literal_cloud_ref: LiteralCloudRefParser,
    source: str = "kill_chain_seed_url",
) -> None:
    refs = list(extract_cloud_asset_seed_refs(seed_value))
    literal_ref = parse_literal_cloud_ref(seed_value)
    if literal_ref is not None and literal_ref not in refs:
        refs.insert(0, literal_ref)
    for asset_type, identifier in refs:
        try:
            con.execute(
                """
                INSERT OR IGNORE INTO cloud_assets
                    (engagement_id, asset_type, identifier, provider_identifier, source)
                VALUES (?, ?, ?, ?, ?)
                """,
                (engagement_id, asset_type, identifier, identifier, source),
            )
        except Exception:  # noqa: BLE001
            pass


def promote_pending_cloud_targets(
    con: Any,
    engagement_id: int,
    targets: Iterable[Mapping[str, Any]],
    *,
    source: str = "kill_chain_cloud_ref",
) -> int:
    inserted = 0
    for target in targets:
        asset_type = str(target.get("service") or "").strip().lower()
        provider_identifier = str(target.get("ref") or "").strip()
        identifier = provider_identifier.lower()
        if not asset_type or not identifier:
            continue
        try:
            cursor = con.execute(
                """
                INSERT INTO cloud_assets
                    (engagement_id, asset_type, identifier, provider_identifier, source)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, asset_type, identifier) DO UPDATE SET
                    provider_identifier = CASE
                        WHEN cloud_assets.provider_identifier IS NULL
                          OR TRIM(cloud_assets.provider_identifier) = ''
                          OR cloud_assets.provider_identifier = cloud_assets.identifier
                        THEN excluded.provider_identifier
                        ELSE cloud_assets.provider_identifier
                    END
                """,
                (engagement_id, asset_type, identifier, provider_identifier, source),
            )
            inserted += int(getattr(cursor, "rowcount", 0) or 0)
        except Exception:  # noqa: BLE001
            continue
    return inserted
