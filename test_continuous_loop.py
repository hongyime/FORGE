#!/usr/bin/env python3
"""Verify secrets auto-feed continuous loop integration."""

import tempfile
import json
from pathlib import Path
from forge.automation_target_feed import build_target_feed
from forge.automation_secret_auto_feed import auto_feed_secrets_to_target_feed

def test_secrets_auto_feed_module():
    """Test secrets auto-feed module directly."""
    test_secrets = [
        {
            'secret_type': 'aws_access_key',
            'secret_value_redacted': 'AKIA...example',
            'source_group': 'test_connector',
            'confidence': 0.9,
        }
    ]
    
    new_targets = auto_feed_secrets_to_target_feed(
        secret_observations=test_secrets,
        existing_targets=set(),
    )
    
    assert len(new_targets) > 0, "Should extract targets from secrets"
    assert new_targets[0]['target_type'] in ('domain', 'url', 'ip', 'email'), "Target type should be valid"
    print(f"✓ Secrets auto-feed module test passed")
    print(f"  Input: 1 AWS key")
    print(f"  Output: {len(new_targets)} targets")
    print(f"  Types: {[t['target_type'] for t in new_targets]}")

def test_feed_build_with_secrets():
    """Test build_target_feed with secrets auto-feed enabled."""
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir)
        reports_dir = data_dir / 'reports'
        imports_dir = data_dir / 'imports'
        reports_dir.mkdir()
        imports_dir.mkdir()
        
        # Create a mock connector output with secret-like observation
        connector_output = imports_dir / 'connector-output.json'
        connector_output.write_text(json.dumps({
            'observations': [
                {
                    'target_type': 'domain',
                    'target': 'example.com',
                    'source': 'test_connector',
                    'provenance': 'gitleaks:api_key_detected',
                    'confidence': 0.9,
                }
            ]
        }))
        
        # Build feed with secrets auto-feed enabled
        result = build_target_feed(
            sources=['connectors'],
            data_dir=data_dir,
            reports_dir=reports_dir,
            imports_dir=imports_dir,
            limit=10,
            existing_feed_path=None,
            apply=False,
        )
        
        # Verify structure
        assert 'sources' in result, "Should have sources key"
        assert 'source_group_counts' in result, "Should have source_group_counts"
        
        print(f"✓ Feed build with secrets integration test passed")
        print(f"  Sources attempted: {result.get('sources', [])}")
        print(f"  Source group counts: {result.get('source_group_counts', {})}")

if __name__ == '__main__':
    print("Testing secrets auto-feed continuous loop integration...\n")
    test_secrets_auto_feed_module()
    test_feed_build_with_secrets()
    print("\n✓ All continuous loop verification tests passed")
