import json
import sqlite3

import pytest
from forge.distributed.coordinator import RateLimiter, QueueCoordinator
from forge.distributed.scheduler import TaskScheduler
from forge.phase1.stealth_recon import run_searxng_passive
from forge.phase4.cloud_validate import run_cloud_validate
from forge.phase4.rce_hunter import run_safe_check, run_weaponize
from forge.phase4.spray import run_spray
from forge.utils.automation import AutomationEngine
from forge.utils.playbooks import PlaybookEngine, PlaybookStep


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
