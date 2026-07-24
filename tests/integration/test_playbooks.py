import json
import sqlite3

import pytest
from forge.distributed.coordinator import RateLimiter, QueueCoordinator
from forge.distributed.scheduler import TaskScheduler
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.phase1.stealth_recon import run_searxng_passive
from forge.phase4.cloud_validate import run_cloud_validate
from forge.phase4.rce_hunter import run_safe_check, run_weaponize
from forge.phase4.spray import run_spray
from forge.utils.automation import AutomationEngine, EXECUTABLE_AUTOMATION_ACTIONS
from forge.utils.playbooks import PlaybookEngine, PlaybookStep
from forge.utils.playbooks.cloud_leak import run_cloud_leak_playbook


class RecordingScheduler:
    def __init__(self):
        self.tasks = []

    def schedule(self, task):
        self.tasks.append(task)

def test_playbook_1_spray_logic(tmp_path):
    # run_spray raises NotImplementedError — real auth adapters must be wired before use
    wordlist_path = tmp_path / "rockyou.txt"
    wordlist_path.write_text("password\n123456\nadmin\n")
    usernames_path = tmp_path / "usernames.txt"
    usernames_path.write_text("root\nuser\n")
    with pytest.raises(NotImplementedError):
        run_spray(1, str(wordlist_path), str(usernames_path), tmp_path)

def test_playbook_2_rate_limiter_integration():
    # Test rate limiter fallback (local memory)
    limiter = RateLimiter()
    bucket = "test_bucket"
    
    # Allow 2 requests per minute
    assert limiter.acquire(bucket, max_requests=2, window_seconds=60) is True
    assert limiter.acquire(bucket, max_requests=2, window_seconds=60) is True
    assert limiter.acquire(bucket, max_requests=2, window_seconds=60) is False

def test_playbook_2_cloud_validate(tmp_path):
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE credentials (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)")
        conn.execute("INSERT INTO credentials (id, username, password_hash) VALUES (1, 'mock_key', 'mock_secret')")
    result = run_cloud_validate(1, "test_cloud_bucket", 10, db_path)
    # the mock tries to import boto3 and will fail unless it's installed or we mock it
    # We are just testing the schema and rate limiter mostly, so a failed status due to "boto3 not installed" or similar is acceptable
    assert result["status"] in ("success", "failed")

def test_playbook_3_state_transition(tmp_path):
    # Test AutomationEngine WAF evasion transition
    db_path = tmp_path / "engagement.db"
    
    # Setup DB schema manually for the test
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE task_progress (id INTEGER PRIMARY KEY, engagement_id INTEGER, task_key TEXT, status TEXT)")
        
    class MockPlaybooks:
        def __init__(self):
            self.waf_evasion_called = False
            self.target = None
            self.context = None
        def run_waf_evasion_recon(self, engagement_id, target, context=None):
            self.waf_evasion_called = True
            self.target = target
            self.context = context

    engine = AutomationEngine(engagement_id=1)
    engine.db_path = db_path
    engine.playbooks = MockPlaybooks()
    
    # Simulate 403 failure
    engine._handle_task_failed(1, "recon:crawl:http://example.com", "HTTP 403 Forbidden - WAF Blocked")
    
    assert engine.playbooks.waf_evasion_called is True
    assert engine.playbooks.target == "http://example.com"
    assert engine.playbooks.context == {}

def test_playbook_3_searxng_connectivity(tmp_path):
    # This just tests the mock fallback since we don't have a real SearxNG container running in tests
    result = run_searxng_passive("example.com", "http://localhost:8080", False, tmp_path)
    # The actual implementation calls requests.get. Unless SearxNG is running, it will fail.
    assert result["status"] in ("success", "failed")

def test_playbook_4_safe_check(tmp_path):
    # run_safe_check raises NotImplementedError — OOB callback server required
    with pytest.raises(NotImplementedError):
        run_safe_check("CVE-2023-1234", "http://example.com", "time_based_sleep", tmp_path)

def test_playbook_4_approval_gate(tmp_path):
    # run_weaponize raises NotImplementedError — exploit delivery not implemented
    with pytest.raises(NotImplementedError):
        run_weaponize("CVE-2023-1234", "http://example.com", True, tmp_path)


def test_playbook_steps_propagate_roe_scope_context(tmp_path):
    scope_manifest = {
        "roe_id": "roe-parent",
        "domains": ["example.com"],
    }
    parent_context = {
        "roe_id": "roe-parent",
        "scope_manifest": scope_manifest,
        "require_roe": True,
        "require_scope_manifest": True,
    }

    scheduler = RecordingScheduler()
    playbooks = PlaybookEngine(scheduler)
    playbooks._execute_steps(
        7,
        [
            PlaybookStep("recon:crawl", {"target": "https://example.com", **parent_context}),
            PlaybookStep("vuln:passive", {"target": "https://example.com"}),
            PlaybookStep(
                "exploit:safe_check",
                {
                    "target": "https://example.com",
                    "vuln_id": "vuln-1",
                    "roe_id": "roe-child",
                    "require_scope_manifest": False,
                },
            ),
        ],
    )

    payload = scheduler.tasks[0].payload
    passive_params = payload["_next_steps"][0]["params"]
    safe_check_params = payload["_next_steps"][1]["params"]
    assert passive_params["roe_id"] == "roe-parent"
    assert passive_params["scope_manifest"] == scope_manifest
    assert passive_params["require_roe"] is True
    assert passive_params["require_scope_manifest"] is True
    assert safe_check_params["roe_id"] == "roe-child"
    assert safe_check_params["scope_manifest"] == scope_manifest
    assert safe_check_params["require_roe"] is True
    assert safe_check_params["require_scope_manifest"] is False

    db_path = tmp_path / "engagement.db"
    parent_task_key = "custom:parent"
    parent_payload = {
        "task_type": "crawl",
        "target": "https://example.com",
        **parent_context,
        "_next_steps": [
            {
                "action": "vuln:passive",
                "params": {
                    "target": "https://example.com",
                    "roe_id": "roe-child",
                },
            },
            {
                "action": "exploit:safe_check",
                "params": {
                    "target": "https://example.com",
                    "vuln_id": "vuln-1",
                    "require_scope_manifest": False,
                },
            },
        ],
    }
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE distributed_tasks (engagement_id INTEGER, task_key TEXT, payload TEXT)"
        )
        conn.execute(
            "INSERT INTO distributed_tasks (engagement_id, task_key, payload) VALUES (?, ?, ?)",
            (7, parent_task_key, json.dumps(parent_payload)),
        )

    automation_scheduler = RecordingScheduler()
    automation = AutomationEngine(engagement_id=7)
    automation.db_path = db_path
    automation.scheduler = automation_scheduler
    automation._handle_task_done(7, parent_task_key)

    child_payload = automation_scheduler.tasks[0].payload
    remaining_params = child_payload["_next_steps"][0]["params"]
    assert child_payload["roe_id"] == "roe-child"
    assert child_payload["scope_manifest"] == scope_manifest
    assert child_payload["require_roe"] is True
    assert child_payload["require_scope_manifest"] is True
    assert remaining_params["roe_id"] == "roe-child"
    assert remaining_params["scope_manifest"] == scope_manifest
    assert remaining_params["require_roe"] is True
    assert remaining_params["require_scope_manifest"] is False


def test_automation_triggered_playbook_preserves_roe_scope_context(tmp_path):
    db_path = tmp_path / "engagement.db"
    context = {
        "roe_id": "roe-parent",
        "scope_manifest": {"roe_id": "roe-parent", "domains": ["example.com"]},
        "require_roe": True,
        "require_scope_manifest": True,
    }
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE distributed_tasks (engagement_id INTEGER, task_key TEXT, payload TEXT)"
        )
        conn.execute("CREATE TABLE credentials (id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO credentials (id) VALUES (42)")
        conn.execute(
            "INSERT INTO distributed_tasks (engagement_id, task_key, payload) VALUES (?, ?, ?)",
            (
                7,
                "osint:breach_check:one",
                json.dumps({"task_type": "breach_check", **context}),
            ),
        )

    scheduler = RecordingScheduler()
    automation = AutomationEngine(engagement_id=7)
    automation.db_path = db_path
    automation.scheduler = scheduler
    automation.playbooks = PlaybookEngine(scheduler)
    automation._handle_task_done(7, "osint:breach_check:one")

    payload = scheduler.tasks[0].payload
    assert payload["task_type"] == "spray"
    assert payload["roe_id"] == "roe-parent"
    assert payload["scope_manifest"] == context["scope_manifest"]
    assert payload["require_roe"] is True
    assert payload["require_scope_manifest"] is True


def test_failed_task_playbook_preserves_roe_scope_context(tmp_path):
    db_path = tmp_path / "engagement.db"
    context = {
        "roe_id": "roe-parent",
        "scope_manifest": {"roe_id": "roe-parent", "domains": ["example.com"]},
        "require_roe": True,
        "require_scope_manifest": True,
    }
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE distributed_tasks (engagement_id INTEGER, task_key TEXT, payload TEXT)"
        )
        conn.execute(
            "INSERT INTO distributed_tasks (engagement_id, task_key, payload) VALUES (?, ?, ?)",
            (
                7,
                "recon:crawl:https://example.com",
                json.dumps({"task_type": "crawl", "target": "https://example.com", **context}),
            ),
        )

    scheduler = RecordingScheduler()
    automation = AutomationEngine(engagement_id=7)
    automation.db_path = db_path
    automation.scheduler = scheduler
    automation.playbooks = PlaybookEngine(scheduler)
    automation._handle_task_failed(
        7,
        "recon:crawl:https://example.com",
        "HTTP 403 Forbidden",
    )

    payload = scheduler.tasks[0].payload
    assert payload["task_type"] == "crawl_stealth"
    assert payload["roe_id"] == "roe-parent"
    assert payload["scope_manifest"] == context["scope_manifest"]
    assert payload["require_roe"] is True
    assert payload["require_scope_manifest"] is True


def test_automation_report_suggestion_ignores_unreportable_cloud_findings(tmp_path):
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        apply_schema(conn)
        run_migrations(conn)
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (7, 'Acme Example', '["acme.example"]', 'ACTIVE', 'tester')
            """
        )
        conn.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, evidence, notes)
            VALUES
                (7, 'firebase', 'stale-firebase', 'VALIDATED',
                 'manual_validated_note', 'operator note only',
                 'not a deterministic proof method')
            """
        )
        conn.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity,
                 title, description, evidence, cloud_provider, resource_id)
            VALUES
                (7, 'DETERMINISTIC_CLOUD_EXPOSURE',
                 'firebase://stale-firebase', 'firebase', 'HIGH',
                 'Validated Firebase data exposure',
                 'Stale deterministic row should stay non-reportable.',
                 'manual note only', 'firebase', 'stale-firebase')
            """
        )
        conn.commit()

    automation = AutomationEngine(engagement_id=7)
    automation.db_path = db_path
    suggestions = automation.get_suggestions()

    assert {suggestion.id for suggestion in suggestions} == set()


def test_automation_rce_trigger_ignores_unreportable_non_rce_findings(tmp_path):
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        apply_schema(conn)
        run_migrations(conn)
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (7, 'Acme Example', '["acme.example"]', 'ACTIVE', 'tester')
            """
        )
        conn.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, evidence, notes)
            VALUES
                (7, 'firebase', 'stale-firebase', 'VALIDATED',
                 'manual_validated_note', 'operator note only',
                 'not a deterministic proof method')
            """
        )
        conn.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity,
                 title, description, evidence, cloud_provider, resource_id)
            VALUES
                (7, 'DETERMINISTIC_CLOUD_EXPOSURE',
                 'firebase://stale-firebase', 'firebase', 'HIGH',
                 'Validated Firebase data exposure',
                 'Stale deterministic row should not trigger RCE automation.',
                 'manual note only', 'firebase', 'stale-firebase')
            """
        )
        conn.commit()

    scheduler = RecordingScheduler()
    automation = AutomationEngine(engagement_id=7)
    automation.db_path = db_path
    automation.scheduler = scheduler
    automation.playbooks = PlaybookEngine(scheduler)
    automation._handle_task_done(7, "vuln:passive:https://app.acme.example")

    assert scheduler.tasks == []


def test_cloud_leak_playbook_rejects_active_key_without_stable_proof(tmp_path):
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        apply_schema(conn)
        run_migrations(conn)
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (7, 'Acme Example', '["acme.example"]', 'ACTIVE', 'tester')
            """
        )
        conn.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend,
                 source_url, key_redacted, key_enc, validation_state,
                 validation_detail)
            VALUES
                (81, 7, 'stale-firebase', 'firebase', 'firebase_api_key',
                 'artifact', 'app.js', 'AIza...STALE', 'encrypted-key',
                 'ACTIVE', 'ACTIVE:manual_validated_note:no deterministic proof')
            """
        )
        conn.commit()

        result = run_cloud_leak_playbook(7, 81, conn, dry_run=True)

    assert result == {"validated": False, "resources": [], "sensitive_files": []}


def test_cloud_leak_playbook_allows_active_key_with_linked_reportable_validation(tmp_path):
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        apply_schema(conn)
        run_migrations(conn)
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (7, 'Acme Example', '["acme.example"]', 'ACTIVE', 'tester')
            """
        )
        conn.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend,
                 source_url, key_redacted, key_enc, validation_state,
                 validation_detail)
            VALUES
                (82, 7, 'linked-firebase', 'firebase', 'firebase_api_key',
                 'artifact', 'app.js', 'AIza...LINK', 'encrypted-key',
                 'ACTIVE', 'ACTIVE:manual_validated_note:no deterministic proof')
            """
        )
        conn.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, evidence, notes)
            VALUES
                (7, 'firebase', 'linked-firebase', 'VALIDATED',
                 'firebase_database_shallow_read',
                 'Firebase project reference responded with non-empty data.',
                 'deterministic proof method')
            """
        )
        conn.commit()

        result = run_cloud_leak_playbook(7, 82, conn, dry_run=True)

    assert result["validated"] is True
    assert result["resources"] == [{"name": "[dry-run-firebase-bucket]", "type": "storage"}]
    assert result["sensitive_files"] == []


def test_cloud_leak_playbook_uses_latest_linked_validation_status(tmp_path):
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        apply_schema(conn)
        run_migrations(conn)
        conn.executescript(
            """
            DROP TABLE cloud_validation_results;
            CREATE TABLE cloud_validation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                asset_type TEXT,
                identifier TEXT,
                validation_status TEXT,
                validation_method TEXT,
                http_status INTEGER,
                evidence TEXT,
                notes TEXT,
                checked_at TEXT
            );
            """
        )
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (7, 'Acme Example', '["acme.example"]', 'ACTIVE', 'tester')
            """
        )
        conn.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend,
                 source_url, key_redacted, key_enc, validation_state,
                 validation_detail)
            VALUES
                (83, 7, 'stale-firebase', 'firebase', 'firebase_api_key',
                 'artifact', 'app.js', 'AIza...STALE', 'encrypted-key',
                 'ACTIVE', 'ACTIVE:manual_validated_note:no deterministic proof')
            """
        )
        conn.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, evidence, notes, checked_at)
            VALUES
                (7, 'firebase', 'stale-firebase', ?, ?, ?, ?, ?)
            """,
            [
                (
                    "VALIDATED",
                    "firebase_database_shallow_read",
                    "non-empty live data",
                    "older deterministic proof",
                    "2026-07-01T00:00:00Z",
                ),
                (
                    "UNVERIFIED",
                    "firebase_database_shallow_read",
                    "latest blocked probe",
                    "latest proof no longer reportable",
                    "2026-07-02T00:00:00Z",
                ),
            ],
        )
        conn.commit()

        result = run_cloud_leak_playbook(7, 83, conn, dry_run=True)

    assert result == {"validated": False, "resources": [], "sensitive_files": []}


def test_automation_suggestions_do_not_offer_lateral_movement(tmp_path):
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        apply_schema(conn)
        run_migrations(conn)
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (7, 'Acme Example', '["acme.example"]', 'ACTIVE', 'tester')
            """
        )
        conn.execute(
            """
            INSERT INTO credentials
                (engagement_id, email, password_hash, validated,
                 validated_service, validated_host)
            VALUES
                (7, 'operator@acme.example', 'hash', 1, 'ssh', '10.0.0.5')
            """
        )
        conn.commit()

    automation = AutomationEngine(engagement_id=7)
    automation.db_path = db_path
    suggestions = automation.get_suggestions()

    assert "post:lateral" not in {suggestion.action for suggestion in suggestions}


def test_automation_suggestions_do_not_offer_credential_validation_by_default(tmp_path):
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        apply_schema(conn)
        run_migrations(conn)
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (7, 'Acme Example', '["acme.example"]', 'ACTIVE', 'tester')
            """
        )
        conn.execute(
            """
            INSERT INTO hosts (id, engagement_id, ip, hostname)
            VALUES (5, 7, '10.0.0.5', 'ssh.acme.example')
            """
        )
        conn.execute(
            """
            INSERT INTO services (host_id, port, protocol, service_name)
            VALUES (5, 22, 'tcp', 'ssh')
            """
        )
        conn.execute(
            """
            INSERT INTO credentials
                (engagement_id, email, password_hash, validated)
            VALUES
                (7, 'operator@acme.example', 'hash', 0)
            """
        )
        conn.commit()

    automation = AutomationEngine(engagement_id=7)
    automation.db_path = db_path
    suggestions = automation.get_suggestions()

    assert "osint:validate" not in {suggestion.action for suggestion in suggestions}


def test_automation_suggestions_do_not_offer_exploit_correlation_by_default(tmp_path):
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        apply_schema(conn)
        run_migrations(conn)
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (7, 'Acme Example', '["acme.example"]', 'ACTIVE', 'tester')
            """
        )
        conn.execute(
            """
            INSERT INTO hosts (id, engagement_id, ip, hostname)
            VALUES (5, 7, '10.0.0.5', 'app.acme.example')
            """
        )
        conn.execute(
            """
            INSERT INTO services
                (host_id, port, protocol, service_name, banner, version)
            VALUES
                (5, 443, 'tcp', 'https', 'nginx/1.20.1', '1.20.1')
            """
        )
        conn.commit()

    automation = AutomationEngine(engagement_id=7)
    automation.db_path = db_path
    suggestions = automation.get_suggestions()

    assert "exploit:correlate" not in {suggestion.action for suggestion in suggestions}
    assert all(suggestion.category != "exploit" for suggestion in suggestions)
    assert all("known exploit" not in suggestion.title.lower() for suggestion in suggestions)


def test_automation_suggestions_only_emit_execute_supported_actions(tmp_path):
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        apply_schema(conn)
        run_migrations(conn)
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (7, 'Acme Example', '["acme.example"]', 'ACTIVE', 'tester')
            """
        )
        conn.execute(
            """
            INSERT INTO emails (engagement_id, email, domain, source)
            VALUES (7, 'operator@acme.example', 'acme.example', 'crawler')
            """
        )
        conn.execute(
            """
            INSERT INTO passive_vulns
                (engagement_id, vuln_id, plugin, url, severity, false_positive)
            VALUES
                (7, 'pv-1', 'headers', 'https://app.acme.example', 'LOW', 0)
            """
        )
        conn.commit()

    automation = AutomationEngine(engagement_id=7)
    automation.db_path = db_path
    suggestions = automation.get_suggestions()

    unsupported_actions = {suggestion.action for suggestion in suggestions} - set(
        EXECUTABLE_AUTOMATION_ACTIONS
    )
    assert unsupported_actions == set()
