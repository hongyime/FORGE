from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, List

from forge.distributed.scheduler import ScheduledTask, TaskScheduler


@dataclass
class PlaybookStep:
    action: str
    params: dict[str, Any]
    depends_on: List[str] = None


class PlaybookEngine:
    def __init__(self, scheduler: TaskScheduler):
        self.scheduler = scheduler

    def run_recon_full(self, engagement_id: int, domain: str):
        steps = [
            PlaybookStep("recon:subdomains", {"domain": domain}),
            PlaybookStep("recon:ports", {"target": domain}),
            PlaybookStep("recon:crawl", {"target": f"http://{domain}"}),
        ]
        self._execute_steps(engagement_id, steps)

    def run_vuln_discovery(self, engagement_id: int, url: str):
        steps = [
            PlaybookStep("recon:crawl", {"target": url}),
            PlaybookStep("vuln:passive", {"target": url}),
            PlaybookStep("vuln:idor", {"target": url}),
        ]
        self._execute_steps(engagement_id, steps)

    def run_zero_to_da(self, engagement_id: int, credential_id: int):
        steps = [
            PlaybookStep("exploit:spray", {
                "credential_id": credential_id,
                "wordlist": "data/wordlists/rockyou.txt",
                "usernames": "data/wordlists/seclists/usernames.txt",
                "requires_approval": True
            })
        ]
        self._execute_steps(engagement_id, steps)

    def run_cloud_leak_loop(self, engagement_id: int, key_id: int):
        import logging
        logging.getLogger(__name__).warning(
            "Cloud Leak playbook (key_id=%d) is not supported in this cycle: "
            "cloud-secret model not yet implemented.  Skipping.",
            key_id,
        )

    def run_waf_evasion_recon(self, engagement_id: int, target: str):
        steps = [
            PlaybookStep("recon:crawl_stealth", {
                "target": target,
                "use_tor": True,
                "jitter_min_ms": 10000,
                "jitter_max_ms": 30000,
                "engine": "playwright"
            }),
            PlaybookStep("recon:searxng_passive", {
                "target": target,
                "searxng_url": "http://searxng:8080",
                "use_tor": True
            })
        ]
        self._execute_steps(engagement_id, steps)

    def run_rce_hunter(self, engagement_id: int, vuln_id: str, target: str):
        steps = [
            PlaybookStep("exploit:safe_check", {
                "vuln_id": vuln_id,
                "target": target,
                "validation_method": "time_based_sleep"
            }),
            PlaybookStep("exploit:weaponize", {
                "vuln_id": vuln_id,
                "target": target,
                "requires_approval": True
            })
        ]
        self._execute_steps(engagement_id, steps)

    def _execute_steps(self, engagement_id: int, steps: List[PlaybookStep]):
        if not steps:
            return
        first_step = steps[0]
        remaining_steps = [
            {"action": s.action, "params": s.params} for s in steps[1:]
        ]
        task_type = first_step.action.split(":")[-1]
        target = first_step.params.get("target", first_step.params.get("domain", "default"))
        task_key = f"{task_type}:{target}:{int(time.time()*1000)}"
        payload = {"task_type": task_type, **first_step.params}
        if remaining_steps:
            payload["_next_steps"] = remaining_steps
        self.scheduler.schedule(
            ScheduledTask(
                engagement_id=engagement_id,
                task_key=task_key,
                payload=payload,
            )
        )
