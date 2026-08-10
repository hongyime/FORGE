"""Phase 5: C2 agent management and orchestration.

Classification: DESTRUCTIVE — requires operator approval.
FORGE_SAFE_MODE=1 blocks all C2 operations.
Manages agent sessions, tasks, and beacon callbacks.
"""

from __future__ import annotations

import logging
import sqlite3
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

from forge.opsec.resilience import _SHUTDOWN, _interruptible_sleep
from forge.phase5.approval_gate import ActionClassification, request_approval

_LOG = logging.getLogger(__name__)


@dataclass
class AgentSession:
    agent_id: str
    host_ip: str
    os_family: str
    username: str
    privilege_level: str = "user"
    last_seen: Optional[str] = None
    tasks_pending: list[dict] = field(default_factory=list)
    tasks_completed: list[dict] = field(default_factory=list)


class C2Orchestrator:
    """Manages C2 agent sessions for an engagement."""

    def __init__(self, engagement_id: int, db: sqlite3.Connection):
        self.engagement_id = engagement_id
        self.db = db
        self.sessions: dict[str, AgentSession] = {}

    def register_agent(
        self,
        agent_id: str,
        host_ip: str,
        os_family: str,
        username: str,
        privilege_level: str = "user",
    ) -> bool:
        """Register a new C2 agent session.

        Requires operator approval (DESTRUCTIVE).
        """
        approved = request_approval(
            "c2_agent_register",
            f"Register C2 agent on {host_ip} as {username} ({os_family})",
            self.engagement_id,
            self.db,
            ActionClassification.DESTRUCTIVE,
        )
        if not approved:
            return False

        import datetime

        session = AgentSession(
            agent_id=agent_id,
            host_ip=host_ip,
            os_family=os_family,
            username=username,
            privilege_level=privilege_level,
            last_seen=datetime.datetime.utcnow().isoformat(),
        )
        self.sessions[agent_id] = session
        print(f"[C2] Agent {agent_id} registered: {username}@{host_ip} ({os_family})", flush=True)
        sys.stdout.flush()
        return True

    def queue_task(
        self,
        agent_id: str,
        command: str,
        classification: ActionClassification = ActionClassification.ACTIVE,
    ) -> bool:
        """Queue a command for execution on agent."""
        if _SHUTDOWN.is_set():
            return False

        session = self.sessions.get(agent_id)
        if not session:
            _LOG.warning("C2: unknown agent %s", agent_id)
            return False

        approved = request_approval(
            "c2_task_queue",
            f"Execute on {session.host_ip}: {command[:80]}",
            self.engagement_id,
            self.db,
            classification,
        )
        if not approved:
            return False

        session.tasks_pending.append({"command": command, "status": "pending"})
        print(f"[C2] Task queued for {agent_id}: {command[:60]}", flush=True)
        sys.stdout.flush()
        return True

    def get_active_sessions(self) -> list[AgentSession]:
        return list(self.sessions.values())

    def terminate_agent(self, agent_id: str) -> None:
        """Terminate a C2 agent session cleanly."""
        if agent_id in self.sessions:
            ip = self.sessions[agent_id].host_ip
            del self.sessions[agent_id]
            print(f"[C2] Agent {agent_id} ({ip}) terminated.", flush=True)
            sys.stdout.flush()


def run_c2_loop(
    orchestrator: C2Orchestrator,
    poll_interval: float = 5.0,
    max_iterations: Optional[int] = None,
) -> None:
    """C2 polling loop — checks for pending tasks and processes callbacks.

    Checks _SHUTDOWN at top of every iteration (RULE 6).
    """
    iteration = 0
    while True:
        if _SHUTDOWN.is_set():
            print("[C2] Shutdown requested — stopping C2 loop.", flush=True)
            break
        if max_iterations is not None and iteration >= max_iterations:
            break

        for agent_id, session in list(orchestrator.sessions.items()):
            if _SHUTDOWN.is_set():
                break
            if session.tasks_pending:
                task = session.tasks_pending.pop(0)
                _LOG.debug("C2: executing task on %s: %s", agent_id, task["command"][:40])
                task["status"] = "dispatched"
                session.tasks_completed.append(task)

        _interruptible_sleep(poll_interval)
        iteration += 1
