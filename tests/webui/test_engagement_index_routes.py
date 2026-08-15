import pytest

from forge.webui.engagement_index_routes import (
    EngagementIndexRouteNotFound,
    engagement_collection_route_payload,
    engagement_detail_route_payload,
    engagement_tombstones_route_payload,
)


def test_engagement_collection_route_payload_builds_authorized_items() -> None:
    payload = engagement_collection_route_payload(
        generated_at="2026-08-14T10:00:00",
        principal="viewer",
        iter_engagement_payloads=lambda principal: [{"id": 1001, "principal": principal}],
    )

    assert payload == {
        "generated_at": "2026-08-14T10:00:00",
        "items": [{"id": 1001, "principal": "viewer"}],
    }


def test_engagement_tombstones_route_payload_preserves_retention_days() -> None:
    payload = engagement_tombstones_route_payload(
        generated_at="2026-08-14T10:00:00",
        retention_days="14",
        principal="viewer",
        iter_missing_engagement_index_payloads=lambda principal: [
            {"id": 1002, "principal": principal}
        ],
    )

    assert payload == {
        "generated_at": "2026-08-14T10:00:00",
        "retention_days": "14",
        "items": [{"id": 1002, "principal": "viewer"}],
    }


def test_engagement_detail_route_payload_resolves_by_ref_and_principal() -> None:
    payload = engagement_detail_route_payload(
        "engagement-1001-acme",
        principal="viewer",
        find_engagement_detail=lambda ref, principal: {
            "slug": ref,
            "principal": principal,
        },
    )

    assert payload == {
        "slug": "engagement-1001-acme",
        "principal": "viewer",
    }


def test_engagement_detail_route_payload_raises_not_found() -> None:
    with pytest.raises(EngagementIndexRouteNotFound, match="Engagement not found"):
        engagement_detail_route_payload(
            "missing",
            principal="viewer",
            find_engagement_detail=lambda _ref, _principal: None,
        )
