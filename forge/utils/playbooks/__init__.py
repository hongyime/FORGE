from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, List

from forge.distributed.scheduler import (
    ScheduledTask,
    TaskScheduler,
    assert_scheduled_task_type_supported,
)

ROE_SCOPE_CONTEXT_KEYS = (
    "roe_id",
    "scope_manifest",
    "require_roe",
    "require_scope_manifest",
)


class PlaybookAuthorizationError(RuntimeError):
    """Raised when a playbook would schedule live work without ROE/scope context."""


def _context_value_present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Mapping):
        return bool(value)
    return value is not None


def has_required_roe_scope_context(metadata: Mapping[str, Any]) -> bool:
    return _context_value_present(metadata.get("roe_id")) and _context_value_present(
        metadata.get("scope_manifest")
    )


def require_roe_scope_context(metadata: Mapping[str, Any]) -> None:
    if not has_required_roe_scope_context(metadata):
        raise PlaybookAuthorizationError(
            "automation playbook scheduling requires roe_id and scope_manifest"
        )


def inherit_roe_scope_context(
    parent_metadata: Mapping[str, Any],
    child_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    inherited = dict(child_metadata)
    for key in ROE_SCOPE_CONTEXT_KEYS:
        if key not in inherited and key in parent_metadata:
            inherited[key] = parent_metadata[key]
    return inherited


def _task_type_from_action(action: str) -> str:
    return str(action or "").split(":")[-1].strip().lower()


@dataclass
class PlaybookStep:
    action: str
    params: dict[str, Any]
    depends_on: List[str] = None


class PlaybookEngine:
    def __init__(self, scheduler: TaskScheduler):
        self.scheduler = scheduler

    def run_recon_full(
        self,
        engagement_id: int,
        domain: str,
        context: Mapping[str, Any] | None = None,
    ):
        steps = [
            PlaybookStep("recon:subdomains", {"domain": domain}),
            PlaybookStep("recon:ports", {"target": domain}),
            PlaybookStep("recon:crawl", {"target": f"http://{domain}"}),
        ]
        self._execute_steps(engagement_id, steps, context=context)

    def run_vuln_discovery(
        self,
        engagement_id: int,
        url: str,
        context: Mapping[str, Any] | None = None,
    ):
        steps = [
            PlaybookStep("recon:crawl", {"target": url}),
            PlaybookStep("vuln:passive", {"target": url}),
            PlaybookStep("vuln:idor", {"target": url}),
        ]
        self._execute_steps(engagement_id, steps, context=context)

    def run_zero_to_da(
        self,
        engagement_id: int,
        credential_id: int,
        context: Mapping[str, Any] | None = None,
    ):
        steps = [
            PlaybookStep("exploit:spray", {
                "credential_id": credential_id,
                "wordlist": "data/wordlists/rockyou.txt",
                "usernames": "data/wordlists/seclists/usernames.txt",
                "requires_approval": True
            })
        ]
        self._execute_steps(engagement_id, steps, context=context)

    def run_cloud_leak_loop(
        self,
        engagement_id: int,
        key_id: int,
        context: Mapping[str, Any] | None = None,
    ):
        payload = inherit_roe_scope_context(
            context or {},
            {
                "task_type": "validate",
                "key_id": int(key_id),
                "require_roe": True,
                "require_scope_manifest": True,
            },
        )
        require_roe_scope_context(payload)
        self.scheduler.schedule(
            ScheduledTask(
                engagement_id=engagement_id,
                task_key=f"validate:key:{int(key_id)}:{int(time.time()*1000)}",
                payload=payload,
            )
        )

    def run_waf_evasion_recon(
        self,
        engagement_id: int,
        target: str,
        context: Mapping[str, Any] | None = None,
    ):
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
        self._execute_steps(engagement_id, steps, context=context)

    def run_rce_hunter(
        self,
        engagement_id: int,
        vuln_id: str,
        target: str,
        context: Mapping[str, Any] | None = None,
    ):
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
        self._execute_steps(engagement_id, steps, context=context)

    def _execute_steps(
        self,
        engagement_id: int,
        steps: List[PlaybookStep],
        context: Mapping[str, Any] | None = None,
    ):
        if not steps:
            return
        for step in steps:
            assert_scheduled_task_type_supported(_task_type_from_action(step.action))
        first_step = steps[0]
        task_type = _task_type_from_action(first_step.action)
        target = first_step.params.get("target", first_step.params.get("domain", "default"))
        task_key = f"{task_type}:{target}:{int(time.time()*1000)}"
        payload = inherit_roe_scope_context(
            context or {},
            {"task_type": task_type, **first_step.params},
        )
        require_roe_scope_context(payload)
        remaining_steps = [
            {
                "action": s.action,
                "params": inherit_roe_scope_context(payload, s.params),
            }
            for s in steps[1:]
        ]
        if remaining_steps:
            payload["_next_steps"] = remaining_steps
        self.scheduler.schedule(
            ScheduledTask(
                engagement_id=engagement_id,
                task_key=task_key,
                payload=payload,
            )
        )
