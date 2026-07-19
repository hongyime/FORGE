from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forge.config import ForgeConfig
from forge.db.session import get_engagement_db
from forge.distributed.coordinator import QueueCoordinator
from forge.distributed.scheduler import TaskScheduler
from forge.utils.playbooks import PlaybookEngine


@dataclass
class Suggestion:
    id: str
    title: str
    action: str
    params: dict[str, Any]
    reason: str
    priority: int  # 1 (low) to 100 (critical)
    category: str  # 'recon', 'vuln', 'exploit', 'report'


class AutomationEngine:
    def __init__(self, engagement_id: int, queue: QueueCoordinator | None = None, scheduler: TaskScheduler | None = None):
        self.engagement_id = engagement_id
        self.cfg = ForgeConfig.load()
        self.db_path = self.cfg.engagement_db_path(str(engagement_id))
        self.queue = queue
        self.scheduler = scheduler
        self.playbooks = PlaybookEngine(scheduler) if scheduler else None

    def run_event_loop(self):
        """Subscribe to forge.events and trigger playbooks automatically based on events."""
        if not self.queue or not self.playbooks:
            return
            
        while True:
            msg = self.queue.consume_topic("forge.events", timeout_seconds=1.0)
            if not msg:
                time.sleep(0.1)
                continue
                
            payload = msg.payload
            event_type = payload.get("message")
            event_data = payload.get("payload", {})
            eng_id = payload.get("engagement_id", self.engagement_id)
            
            if event_type == "task_done":
                task_key = event_data.get("task_key", "")
                self._handle_task_done(eng_id, task_key)
            elif event_type == "task_failed":
                task_key = event_data.get("task_key", "")
                error = event_data.get("error", "")
                self._handle_task_failed(eng_id, task_key, error)

    def _handle_task_done(self, engagement_id: int, task_key: str):
        # Check for chained next steps
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT payload FROM distributed_tasks WHERE engagement_id=? AND task_key=?", (engagement_id, task_key)).fetchone()
            if row and row["payload"]:
                try:
                    payload_dict = json.loads(row["payload"])
                    next_steps = payload_dict.get("_next_steps", [])
                    if next_steps and self.scheduler:
                        next_step_data = next_steps[0]
                        remaining = next_steps[1:]
                        
                        n_action = next_step_data["action"]
                        n_params = next_step_data["params"]
                        n_task_type = n_action.split(":")[-1]
                        n_target = n_params.get("target", n_params.get("domain", "default"))
                        
                        import time
                        n_task_key = f"{n_task_type}:{n_target}:{int(time.time()*1000)}"
                        
                        n_payload = {"task_type": n_task_type, **n_params}
                        if remaining:
                            n_payload["_next_steps"] = remaining
                            
                        from forge.distributed.scheduler import ScheduledTask
                        self.scheduler.schedule(
                            ScheduledTask(
                                engagement_id=engagement_id,
                                task_key=n_task_key,
                                payload=n_payload
                            )
                        )
                except Exception:
                    pass

        # Trigger Playbook 1 (Zero-to-DA) if a new credential is breached or cracked
        if task_key.startswith("osint:breach_check") or task_key.startswith("exploit:crack"):
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                # Just get the latest credential id as a simplification for trigger
                row = conn.execute("SELECT id FROM credentials ORDER BY id DESC LIMIT 1").fetchone()
                if row:
                    self.playbooks.run_zero_to_da(engagement_id, row["id"])

        # Cloud Leak playbook trigger disabled — no cloud-secret model exists yet.
        # The credentials table has no 'description' column, and breach credentials
        # should not be treated as cloud secrets. See BF-007 / BF-016.
        if task_key.startswith("recon:secret_scan"):
            import logging
            logging.getLogger(__name__).info(
                "Cloud Leak playbook trigger skipped: cloud-secret model not yet implemented."
            )

        # Trigger Playbook 4 (RCE Hunter) if passive vuln scan finishes
        if task_key.startswith("vuln:passive") or task_key.startswith("recon:ports"):
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                # Example: finding an RCE vulnerability
                row = conn.execute("SELECT id, host_id FROM vulnerability_findings WHERE severity IN ('high', 'critical') ORDER BY id DESC LIMIT 1").fetchone()
                if row:
                    # simplistic target extraction
                    host_row = conn.execute("SELECT ip FROM hosts WHERE id = ?", (row["host_id"],)).fetchone()
                    if host_row:
                        self.playbooks.run_rce_hunter(engagement_id, str(row["id"]), host_row["ip"])

    def _handle_task_failed(self, engagement_id: int, task_key: str, error: str):
        # Example triggering Playbook 3 (WAF Evasion) if a task fails due to 403
        if "403" in error or "WAF" in error or "429" in error:
            if task_key.startswith("recon:crawl:") or task_key.startswith("recon:ports:"):
                target = task_key.split(":", 2)[-1]
                self.playbooks.run_waf_evasion_recon(engagement_id, target)

    def get_suggestions(self) -> list[Suggestion]:
        if not self.db_path.exists():
            return []

        suggestions: list[Suggestion] = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # 1. Recon: Ports and Crawls
            self._suggest_port_scans(conn, suggestions)
            self._suggest_crawls(conn, suggestions)
            
            # 2. Intelligence: Credential Validation & OSINT
            self._suggest_credential_validation(conn, suggestions)
            self._suggest_osint_enrichment(conn, suggestions)
            
            # 3. Vulnerability: Scanning & Correlation
            self._suggest_vuln_scans(conn, suggestions)
            self._suggest_correlation(conn, suggestions)
            
            # 4. Post-Exploit: Lateral Movement & Exfil
            self._suggest_lateral_movement(conn, suggestions)
            
            # 5. Reporting
            self._suggest_reporting(conn, suggestions)

        return sorted(suggestions, key=lambda x: x.priority, reverse=True)

    def _suggest_credential_validation(self, conn: sqlite3.Connection, suggestions: list[Suggestion]) -> None:
        # Find unvalidated credentials and hosts with matching services
        creds = conn.execute(
            "SELECT id, email, password_hash FROM credentials WHERE engagement_id = ? AND validated = 0",
            (self.engagement_id,),
        ).fetchall()
        
        if not creds:
            return

        services = conn.execute(
            """
            SELECT h.ip, s.service_name 
            FROM services s 
            JOIN hosts h ON s.host_id = h.id 
            WHERE h.engagement_id = ? AND s.service_name IN ('ssh', 'rdp', 'smb', 'ftp')
            """,
            (self.engagement_id,),
        ).fetchall()

        for cred in creds:
            for svc in services:
                suggestions.append(
                    Suggestion(
                        id=f"cred-val-{cred['id']}-{svc['ip']}",
                        title=f"Validate {cred['email']} on {svc['ip']} ({svc['service_name']})",
                        action="osint:validate",
                        params={
                            "engagement_id": self.engagement_id,
                            "host": svc["ip"],
                            "service": svc["service_name"],
                            "credential_id": cred["id"]
                        },
                        reason=f"Unvalidated credential found; service {svc['service_name']} available on {svc['ip']}.",
                        priority=95,
                        category="exploit",
                    )
                )

    def _suggest_osint_enrichment(self, conn: sqlite3.Connection, suggestions: list[Suggestion]) -> None:
        # Suggest DeHashed or XposedOrNot for new emails
        emails = conn.execute(
            """
            SELECT email FROM emails 
            WHERE engagement_id = ? 
            AND NOT EXISTS (
                SELECT 1 FROM email_intelligence ei 
                WHERE ei.engagement_id = ? AND ei.email = emails.email
            )
            """,
            (self.engagement_id, self.engagement_id),
        ).fetchall()

        if emails:
            suggestions.append(
                Suggestion(
                    id="osint-email-enrich",
                    title=f"Enrich {len(emails)} emails via breach intelligence",
                    action="osint:dehashed",
                    params={"engagement_id": self.engagement_id, "query_type": "email", "query_value": emails[0]["email"]},
                    reason=f"Found {len(emails)} new emails; ready for exposure check.",
                    priority=65,
                    category="recon",
                )
            )

    def _suggest_lateral_movement(self, conn: sqlite3.Connection, suggestions: list[Suggestion]) -> None:
        # If we have a successful credential validation, suggest lateral movement
        valid_creds = conn.execute(
            "SELECT validated_host, validated_service FROM credentials WHERE engagement_id = ? AND validated = 1",
            (self.engagement_id,),
        ).fetchall()

        for cred in valid_creds:
            suggestions.append(
                Suggestion(
                    id=f"lateral-{cred['validated_host']}",
                    title=f"Attempt lateral movement from {cred['validated_host']}",
                    action="post:lateral",
                    params={"engagement_id": self.engagement_id, "target": cred["validated_host"]},
                    reason=f"Valid credentials confirmed on {cred['validated_host']}.",
                    priority=100,
                    category="exploit",
                )
            )

    def _suggest_port_scans(self, conn: sqlite3.Connection, suggestions: list[Suggestion]) -> None:
        # Find hosts that aren't in the services table yet
        rows = conn.execute(
            """
            SELECT h.ip, h.hostname 
            FROM hosts h
            LEFT JOIN services s ON h.id = s.host_id
            WHERE h.engagement_id = ? AND s.id IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM task_progress tp 
                WHERE tp.engagement_id = ? 
                AND tp.task_key LIKE 'ports:%' || h.ip
                AND tp.status IN ('pending', 'running', 'complete')
            )
            """,
            (self.engagement_id, self.engagement_id),
        ).fetchall()

        for row in rows:
            target = row["ip"]
            suggestions.append(
                Suggestion(
                    id=f"port-scan-{target}",
                    title=f"Scan ports on {target}",
                    action="recon:ports",
                    params={"target": target, "engagement_id": self.engagement_id},
                    reason=f"New host {target} discovered but no ports scanned yet.",
                    priority=80,
                    category="recon",
                )
            )

    def _suggest_crawls(self, conn: sqlite3.Connection, suggestions: list[Suggestion]) -> None:
        # Find HTTP/HTTPS services that haven't been crawled
        rows = conn.execute(
            """
            SELECT h.ip, s.port, s.protocol, s.service_name
            FROM services s
            JOIN hosts h ON s.host_id = h.id
            WHERE h.engagement_id = ?
            AND (s.port IN (80, 443, 8080, 8443) OR s.service_name LIKE '%http%')
            AND NOT EXISTS (
                SELECT 1 FROM crawl_results cr 
                WHERE cr.engagement_id = ? 
                AND (cr.url LIKE '%' || h.ip || ':' || s.port || '%' OR cr.url LIKE '%' || h.ip || '%')
            )
            AND NOT EXISTS (
                SELECT 1 FROM task_progress tp 
                WHERE tp.engagement_id = ? 
                AND tp.task_key LIKE 'crawl:%' || h.ip || ':' || s.port
                AND tp.status IN ('pending', 'running', 'complete')
            )
            """,
            (self.engagement_id, self.engagement_id, self.engagement_id),
        ).fetchall()

        for row in rows:
            proto = "https" if row["port"] in (443, 8443) else "http"
            target = f"{proto}://{row['ip']}:{row['port']}"
            suggestions.append(
                Suggestion(
                    id=f"crawl-{row['ip']}-{row['port']}",
                    title=f"Crawl web service at {target}",
                    action="recon:crawl",
                    params={"target": target, "engagement_id": self.engagement_id},
                    reason=f"Active web service found on {row['ip']}:{row['port']}.",
                    priority=70,
                    category="recon",
                )
            )

    def _suggest_vuln_scans(self, conn: sqlite3.Connection, suggestions: list[Suggestion]) -> None:
        # Suggest passive scans for crawled URLs
        rows = conn.execute(
            """
            SELECT DISTINCT final_url 
            FROM crawl_results 
            WHERE engagement_id = ?
            AND NOT EXISTS (
                SELECT 1 FROM passive_vulns pv 
                WHERE pv.engagement_id = ? AND pv.url = crawl_results.final_url
            )
            AND NOT EXISTS (
                SELECT 1 FROM task_progress tp 
                WHERE tp.engagement_id = ? 
                AND tp.task_key LIKE 'vuln:passive:%' || crawl_results.final_url
                AND tp.status IN ('pending', 'running', 'complete')
            )
            """,
            (self.engagement_id, self.engagement_id, self.engagement_id),
        ).fetchall()

        for row in rows:
            url = row["final_url"]
            suggestions.append(
                Suggestion(
                    id=f"vuln-passive-{url}",
                    title=f"Run passive vuln scan on {url}",
                    action="vuln:passive",
                    params={"target": url, "engagement_id": self.engagement_id},
                    reason=f"Web content crawled for {url}; ready for passive analysis.",
                    priority=60,
                    category="vuln",
                )
            )

    def _suggest_correlation(self, conn: sqlite3.Connection, suggestions: list[Suggestion]) -> None:
        # If we have services with versions, suggest exploit correlation
        row = conn.execute(
            """
            SELECT COUNT(*) as count 
            FROM services s
            JOIN hosts h ON s.host_id = h.id
            WHERE h.engagement_id = ? AND s.version IS NOT NULL
            """,
            (self.engagement_id,),
        ).fetchone()

        if row and row["count"] > 0:
            # Check if correlation task already ran
            check = conn.execute(
                """
                SELECT 1 FROM task_progress 
                WHERE engagement_id = ? AND task_key = 'exploit:correlate'
                AND status = 'complete'
                """,
                (self.engagement_id,),
            ).fetchone()

            if not check:
                suggestions.append(
                    Suggestion(
                        id="exploit-correlate",
                        title="Correlate services with known exploits",
                        action="exploit:correlate",
                        params={"engagement_id": self.engagement_id},
                        reason=f"Found {row['count']} services with version strings.",
                        priority=90,
                        category="exploit",
                    )
                )

    def _suggest_reporting(self, conn: sqlite3.Connection, suggestions: list[Suggestion]) -> None:
        # If we have any findings, suggest generating a report
        row = conn.execute(
            """
            SELECT 
                (SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id = ?) +
                (SELECT COUNT(*) FROM passive_vulns WHERE engagement_id = ?) as total
            """,
            (self.engagement_id, self.engagement_id),
        ).fetchone()

        if row and row["total"] > 0:
            suggestions.append(
                Suggestion(
                    id="report-generate",
                    title="Generate interim engagement report",
                    action="report:generate",
                    params={"engagement_id": self.engagement_id},
                    reason=f"Found {row['total']} total vulnerabilities/findings.",
                    priority=40,
                    category="report",
                )
            )
