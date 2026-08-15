from __future__ import annotations

import json

from forge.active_validation import graph_scenarios
from forge.active_validation.graph_scenarios import (
    draft_active_validation_scenarios_from_asset_graph,
)


def test_graph_scenarios_draft_safe_offline_jobs_from_attack_paths(monkeypatch) -> None:
    def fake_graph(con, engagement_id: int, *, limit: int) -> dict:
        assert engagement_id == 1001
        assert limit >= 25
        return {
            "attack_paths": [
                {
                    "path_id": "path:1",
                    "score": 91.2,
                    "nodes": [
                        {
                            "node_id": 10,
                            "entity_key": "host:app.example",
                            "entity_type": "host",
                            "label": "https://user:pass@app.example/?token=never",
                        },
                        {
                            "node_id": 11,
                            "entity_key": "identity:gcp:serviceAccount:ops@example.iam.gserviceaccount.com",
                            "entity_type": "identity",
                            "risk_score": 88.0,
                        },
                        {
                            "node_id": 12,
                            "entity_key": "cloud:gcp:bucket:public-sensitive",
                            "entity_type": "cloud",
                            "risk_score": 94.0,
                        },
                    ],
                    "exposure_summary": {
                        "terminal_entity_key": "cloud:gcp:bucket:public-sensitive",
                        "summary": "https://app.example/?secret=never reaches sensitive data",
                        "risk_tags": ["internet_exposed", "sensitive_data"],
                    },
                }
            ],
            "minimal_fix_set_candidates": [
                {
                    "node_id": 20,
                    "entity_key": "finding:exposed-admin",
                    "entity_type": "finding",
                    "reason": "remediate_highest_risk_finding",
                    "risk_tags": ["internet_exposed"],
                }
            ],
            "critical_assets": [],
        }

    monkeypatch.setattr(graph_scenarios, "list_asset_graph", fake_graph)

    drafts = draft_active_validation_scenarios_from_asset_graph(
        object(),
        1001,
        limit=5,
    )

    assert [
        (draft["target_ref"], draft["target_kind"], draft["method"], draft["mode"])
        for draft in drafts
    ] == [
        ("host:app.example", "host", "http_reachability", "dry_run"),
        ("cloud:gcp:bucket:public-sensitive", "cloud", "control_simulation", "lab"),
        ("finding:exposed-admin", "finding", "fix_verification", "dry_run"),
    ]
    assert all(draft["safe_profile"] == "non_destructive" for draft in drafts)
    assert all(draft["approved"] is False for draft in drafts)
    assert all(draft["approval_required"] is False for draft in drafts)
    assert all(draft["network_execution"] is False for draft in drafts)

    blob = json.dumps(drafts, sort_keys=True)
    assert "token=never" not in blob
    assert "secret=never" not in blob
    assert "user:pass" not in blob


def test_graph_scenarios_fall_back_to_critical_cloud_and_identity_assets(monkeypatch) -> None:
    monkeypatch.setattr(
        graph_scenarios,
        "list_asset_graph",
        lambda *_args, **_kwargs: {
            "attack_paths": [],
            "minimal_fix_set_candidates": [],
            "critical_assets": [
                {
                    "node_id": 30,
                    "entity_key": "identity:aws:role:Admin",
                    "entity_type": "identity",
                    "tags": ["wildcard_action", "token_should_not_be_key"],
                },
                {
                    "node_id": 31,
                    "entity_key": "cloud:aws:s3:public",
                    "entity_type": "cloud",
                    "tags": ["internet_exposed", "sensitive_data"],
                },
            ],
        },
    )

    drafts = draft_active_validation_scenarios_from_asset_graph(object(), 1001, limit=10)

    assert [
        (draft["target_ref"], draft["target_kind"], draft["method"], draft["mode"])
        for draft in drafts
    ] == [
        ("identity:aws:role:Admin", "identity", "control_simulation", "lab"),
        ("cloud:aws:s3:public", "cloud", "control_simulation", "lab"),
    ]
    assert "token_should_not_be_key" in drafts[0]["risk_tags"]
