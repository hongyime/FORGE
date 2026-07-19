from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from forge.config import ForgeConfig
from forge.db.session import get_engagement_db

_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_LOCAL_PARTS: tuple[str, ...] = (
    "admin",
    "security",
    "helpdesk",
    "it",
    "hr",
    "support",
    "info",
    "devops",
)


def extract_emails(text: str) -> list[str]:
    matches = _EMAIL_RE.findall(text)
    seen: set[str] = set()
    return [x.lower() for x in matches if not (x.lower() in seen or seen.add(x.lower()))]


def run_email_harvest(
    engagement_id: str | int,
    domain: str,
    db_path: Path | None = None,
    operator: str | None = None,
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> list[str]:
    cfg = ForgeConfig.load()
    eng_id = int(engagement_id)
    target_db = db_path or cfg.engagement_db_path(str(engagement_id))
    op = operator or cfg.operator

    conn = get_engagement_db(target_db)
    discovered: list[str] = []
    try:
        candidates = [f"{local}@{domain}" for local in _LOCAL_PARTS]
        host_rows = conn.execute(
            "SELECT hostname FROM hosts WHERE engagement_id=? AND hostname IS NOT NULL",
            (eng_id,),
        ).fetchall()
        host_text = " ".join([str(r["hostname"]) for r in host_rows])
        extracted = extract_emails(host_text)
        all_emails = list(dict.fromkeys(candidates + extracted))
        total = len(all_emails)
        for index, email in enumerate(all_emails, start=1):
            domain_part = email.split("@", maxsplit=1)[-1]
            conn.execute(
                """
                INSERT INTO emails (engagement_id, email, domain, source)
                VALUES (?, ?, ?, 'phase1_harvest')
                ON CONFLICT(engagement_id, email) DO NOTHING
                """,
                (eng_id, email, domain_part),
            )
            discovered.append(email)
            if progress_callback is not None:
                progress_callback(index, total, email)
        conn.execute(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
            VALUES (?, 'phase1', 'email_harvester', 'harvest', ?, 'ok', ?)
            """,
            (eng_id, domain, op),
        )
        conn.commit()
    finally:
        conn.close()

    return discovered
