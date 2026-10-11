"""Tests for the new default scope manifest and starter target feed.

These lock in the shape of the shipped templates so refactors do not
silently drop the goal lock v2 permission blocks or break the starter
feed schema version used by ``forge targets import``.
"""

from __future__ import annotations

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_default_scope_manifest_shape() -> None:
    manifest_path = REPO_ROOT / "manifests" / "default.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert data["roe_id"] == "ROE-1"
    assert isinstance(data["domains"], list)
    assert isinstance(data["urls"], list)
    assert isinstance(data["ip_ranges"], list)
    assert isinstance(data["authorized_seeds"], list)
    permissions = data["permissions"]
    assert permissions["reverse_proxy"] is True
    assert permissions["post_login_automation"] is True
    assert permissions["autonomous_exploit"] is True
    goal_targets = permissions["goal_targets"]
    expected_goals = {
        "get_domain_admin",
        "exfiltrate_proof_data",
        "establish_persistence",
        "capture_mfa_session",
        "achieve_rce",
        "escalate_privilege",
        "enumerate_tenant",
    }
    assert expected_goals.issubset(set(goal_targets))


def test_starter_target_feed_shape() -> None:
    feed_path = REPO_ROOT / "imports" / "starter-targets.example.json"
    data = json.loads(feed_path.read_text(encoding="utf-8"))

    assert data["schema"] == "target-feed.v1"
    assert data["source"] == "forge-starter-example"
    targets = data["targets"]
    assert isinstance(targets, list) and targets
    seen_types = {entry["type"] for entry in targets}
    assert {"domain", "url", "email", "ipv4"}.issubset(seen_types)
    for entry in targets:
        assert "value" in entry
        assert entry["source_group"] == "starter"
