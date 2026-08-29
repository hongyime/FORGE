from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any

_SERVICE_GUIDANCE: dict[str, dict[str, Any]] = {
    "aws": {
        "rotation_summary": "Disable or delete the exposed access key, create a replacement only if the workload still needs it, then audit recent CloudTrail use.",
        "provider_docs": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
        ],
        "validation_after_revocation": "Run the existing Forge key validation sweep; expected state is REVOKED or UNCONFIRMED with no authenticated account proof.",
    },
    "github": {
        "rotation_summary": "Revoke the exposed token from GitHub developer settings or the owning GitHub App, then rotate any dependent automation secret.",
        "provider_docs": [
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation",
        ],
        "validation_after_revocation": "Re-run GitHub token validation or code search; expected state is REVOKED/UNCONFIRMED and no new matching public hit.",
    },
    "gitlab": {
        "rotation_summary": "Revoke the exposed personal, project, group, or deploy token and rotate dependent CI/CD variables.",
        "provider_docs": [
            "https://docs.gitlab.com/user/profile/personal_access_tokens/",
        ],
        "validation_after_revocation": "Re-run token validation or configured repository scan; expected state is REVOKED/UNCONFIRMED.",
    },
    "slack": {
        "rotation_summary": "Revoke or rotate the Slack token from the owning app, then review workspace audit logs for token use.",
        "provider_docs": ["https://api.slack.com/authentication/token-types"],
        "validation_after_revocation": "Re-run Slack auth.test validation; expected state is REVOKED/UNCONFIRMED.",
    },
    "stripe": {
        "rotation_summary": "Roll the exposed API key in Stripe Dashboard, update dependent services, then remove the old key.",
        "provider_docs": ["https://docs.stripe.com/keys"],
        "validation_after_revocation": "Re-run Stripe key validation; expected state is REVOKED/UNCONFIRMED.",
    },
    "sendgrid": {
        "rotation_summary": "Delete the exposed SendGrid API key, create a scoped replacement, and review recent mail/API activity.",
        "provider_docs": ["https://docs.sendgrid.com/ui/account-and-settings/api-keys"],
        "validation_after_revocation": "Re-run SendGrid key validation; expected state is REVOKED/UNCONFIRMED.",
    },
    "twilio": {
        "rotation_summary": "Rotate the exposed Twilio Auth Token or API key and review account usage for unexpected activity.",
        "provider_docs": ["https://www.twilio.com/docs/iam/api-keys"],
        "validation_after_revocation": "Re-run Twilio validation; expected state is REVOKED/UNCONFIRMED.",
    },
    "telegram": {
        "rotation_summary": "Revoke or regenerate the bot token with BotFather, then update the legitimate bot runtime.",
        "provider_docs": ["https://core.telegram.org/bots/features#botfather"],
        "validation_after_revocation": "Re-run Telegram getMe validation; expected state is REVOKED/UNCONFIRMED.",
    },
    "discord": {
        "rotation_summary": "Regenerate the bot token in the Discord developer portal and redeploy dependent automation.",
        "provider_docs": ["https://discord.com/developers/docs/topics/oauth2"],
        "validation_after_revocation": "Re-run Discord current-user validation; expected state is REVOKED/UNCONFIRMED.",
    },
    "openai": {
        "rotation_summary": "Revoke the exposed API key, create a replacement with least privilege/project scoping, and review usage.",
        "provider_docs": ["https://platform.openai.com/api-keys"],
        "validation_after_revocation": "Re-run OpenAI validation; expected state is REVOKED/UNCONFIRMED.",
    },
    "anthropic": {
        "rotation_summary": "Revoke the exposed API key, rotate dependent secrets, and review organization usage.",
        "provider_docs": ["https://console.anthropic.com/settings/keys"],
        "validation_after_revocation": "Re-run Anthropic validation; expected state is REVOKED/UNCONFIRMED.",
    },
    "azure": {
        "rotation_summary": "Regenerate the exposed Azure key/connection string or rotate the affected service principal credential.",
        "provider_docs": ["https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"],
        "validation_after_revocation": "Re-run Azure validation; expected state is REVOKED/UNCONFIRMED.",
    },
    "google": {
        "rotation_summary": "Restrict, rotate, or delete the exposed Google API key/service credential and review API usage.",
        "provider_docs": ["https://cloud.google.com/docs/authentication/api-keys"],
        "validation_after_revocation": "Re-run Google validation; expected state is REVOKED/UNCONFIRMED.",
    },
}

_PREVENTION_GUIDANCE: list[dict[str, str]] = [
    {
        "workflow": "pre-commit",
        "tool": "gitleaks",
        "command": "gitleaks protect --staged --redact",
        "cost": "free/local",
    },
    {
        "workflow": "pre-commit",
        "tool": "detect-secrets",
        "command": "detect-secrets-hook --baseline .secrets.baseline",
        "cost": "free/local",
    },
    {
        "workflow": "pull_request",
        "tool": "gitleaks",
        "command": "gitleaks detect --source . --redact --exit-code 1",
        "cost": "free/local",
    },
    {
        "workflow": "push",
        "tool": "trufflehog",
        "command": "trufflehog git file://. --only-verified --json",
        "cost": "free/local",
    },
]
_PREVENTION_WORKFLOW_TARGETS: dict[str, dict[str, str]] = {
    "pre-commit": {
        "artifact": ".pre-commit-config.yaml",
        "trigger": "git commit",
        "mode": "blocking local hook",
    },
    "pull_request": {
        "artifact": ".github/workflows/forge-secret-scan.yml",
        "trigger": "pull_request",
        "mode": "blocking CI check",
    },
    "push": {
        "artifact": ".git/hooks/pre-push or provider push protection",
        "trigger": "git push",
        "mode": "blocking local/provider check",
    },
}
_PREVENTION_WORKFLOW_ALIASES = {
    "all": "",
    "*": "",
    "pre_commit": "pre-commit",
    "pre-commit": "pre-commit",
    "commit": "pre-commit",
    "pull_request": "pull_request",
    "pull-request": "pull_request",
    "pr": "pull_request",
    "ci": "pull_request",
    "push": "push",
    "pre_push": "push",
    "pre-push": "push",
}
_FORBIDDEN_METADATA_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "hash_plaintext",
    "key_enc",
    "key_raw",
    "password",
    "password_enc",
    "password_hash",
    "password_plaintext_enc",
    "refresh_token",
    "secret",
    "token",
}
_FORBIDDEN_KEY_FRAGMENTS = ("authorization", "password", "secret", "token")
_SECRET_REMEDIATION_TERMINAL_STATUSES = {"risk_accepted", "resolved", "false_positive"}


def _ensure_rows(con: sqlite3.Connection) -> None:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _scrub_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        scrubbed: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if lowered in _FORBIDDEN_METADATA_KEYS:
                continue
            if any(fragment in lowered for fragment in _FORBIDDEN_KEY_FRAGMENTS):
                if lowered != "key_redacted":
                    continue
            scrubbed[key] = _scrub_value(raw_value)
        return scrubbed
    if isinstance(value, list):
        return [_scrub_value(item) for item in value]
    if isinstance(value, tuple):
        return [_scrub_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _json_dump(value: Mapping[str, Any] | list[Any], *, scrub: bool = False) -> str:
    payload = _scrub_value(value) if scrub else value
    return json.dumps(payload, sort_keys=True)


def _json_load(value: object) -> Any:
    if isinstance(value, (dict, list)):
        return value
    text = str(value or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def _service_key(service: object) -> str:
    text = str(service or "").strip().lower()
    aliases = {
        "aws_access_key": "aws",
        "aws_secret_access_key": "aws",
        "github_pat": "github",
        "google_api_key": "google",
        "gcp": "google",
        "azure_storage": "azure",
        "openai_api_key": "openai",
        "anthropic_api_key": "anthropic",
    }
    return aliases.get(text, text)


def revocation_guidance_for_secret(service: object, pattern_name: object = "") -> dict[str, Any]:
    service_name = _service_key(service)
    guidance = dict(
        _SERVICE_GUIDANCE.get(
            service_name,
            {
                "rotation_summary": "Revoke or rotate the exposed credential with the owning provider, then redeploy dependent services.",
                "provider_docs": [],
                "validation_after_revocation": "Re-run Forge validation; expected state is REVOKED or UNCONFIRMED.",
            },
        )
    )
    guidance.update(
        {
            "service": service_name or str(service or ""),
            "pattern_name": str(pattern_name or ""),
            "secret_material_policy": "Do not paste or store the raw secret in tickets, suppressions, or comments; use redacted key and finding id.",
        }
    )
    return guidance


def prevention_guidance_for_secret(service: object) -> list[dict[str, str]]:
    service_name = _service_key(service)
    guidance = [dict(item) for item in _PREVENTION_GUIDANCE]
    if service_name == "github":
        guidance.append(
            {
                "workflow": "push",
                "tool": "GitHub secret protection",
                "command": "Enable secret scanning and push protection on the repository or organization when available.",
                "cost": "free/plan-dependent",
            }
        )
    return guidance


def _normalize_prevention_workflow(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return _PREVENTION_WORKFLOW_ALIASES.get(text, text)


def _unique_sorted_strings(values: list[str]) -> list[str]:
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _unique_sorted_ints(values: list[int]) -> list[int]:
    return sorted({int(value) for value in values if int(value) > 0})


def _workflow_artifact_template(
    workflow_id: str,
    commands: list[dict[str, Any]],
) -> dict[str, str]:
    """Return review-only prevention artifact content without secret values."""
    command_lines = [
        str(item.get("command") or "").strip()
        for item in commands
        if str(item.get("command") or "").strip()
    ]
    if workflow_id == "pre-commit":
        hook_blocks = []
        for index, command in enumerate(command_lines, start=1):
            hook_blocks.append(
                "\n".join(
                    [
                        f"      - id: forge-secret-scan-{index}",
                        f"        name: Forge secret prevention {index}",
                        f"        entry: {command}",
                        "        language: system",
                        "        pass_filenames: false",
                    ]
                )
            )
        content = "\n".join(
            [
                "repos:",
                "  - repo: local",
                "    hooks:",
                *hook_blocks,
                "",
            ]
        )
        return {
            "artifact": ".pre-commit-config.yaml",
            "content_type": "text/yaml",
            "content": content,
        }
    if workflow_id == "pull_request":
        steps = []
        for index, command in enumerate(command_lines, start=1):
            steps.extend(
                [
                    f"      - name: Forge secret scan {index}",
                    f"        run: {command}",
                ]
            )
        content = "\n".join(
            [
                "name: Forge Secret Scan",
                "on:",
                "  pull_request:",
                "  workflow_dispatch:",
                "jobs:",
                "  secret-scan:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - uses: actions/checkout@v4",
                *steps,
                "",
            ]
        )
        return {
            "artifact": ".github/workflows/forge-secret-scan.yml",
            "content_type": "text/yaml",
            "content": content,
        }
    if workflow_id == "push":
        command_block = "\n".join(
            f'echo "+ {command}"\n{command}' for command in command_lines
        )
        content = "\n".join(
            [
                "#!/usr/bin/env sh",
                "set -eu",
                "# Forge secret prevention: value-free local pre-push gate.",
                command_block,
                "",
            ]
        )
        return {
            "artifact": ".git/hooks/pre-push",
            "content_type": "text/x-shellscript",
            "content": content,
        }
    return {"artifact": "", "content_type": "text/plain", "content": ""}


def secret_prevention_workflow_plan(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    workflow: str = "",
) -> dict[str, Any]:
    """Return value-free pre-commit/PR/push prevention commands for lifecycle rows."""
    _ensure_rows(con)
    requested_workflow = _normalize_prevention_workflow(workflow)
    if requested_workflow and requested_workflow not in _PREVENTION_WORKFLOW_TARGETS:
        raise ValueError(
            "workflow must be one of: all, pre-commit, pull_request, push",
        )
    if _table_exists(con, "key_scanner_findings") and _table_exists(con, "secret_lifecycle_items"):
        lifecycle_sync = sync_secret_lifecycle(con, int(engagement_id))
    else:
        lifecycle_sync = {"engagement_id": int(engagement_id), "synced": 0}
    if not _table_exists(con, "secret_lifecycle_items"):
        return {
            "schema": "forge.secret_prevention.v1",
            "schema_version": "forge.secret_prevention.v1",
            "execution_policy": "plan_only_secret_prevention_no_commands_executed",
            "total_count": 0,
            "selected_count": 0,
            "omitted_count": 0,
            "engagement_id": int(engagement_id),
            "workflow_filter": requested_workflow or "all",
            "lifecycle_sync": lifecycle_sync,
            "summary": {
                "workflow_count": 0,
                "command_count": 0,
                "finding_count": 0,
                "suppressed_count": 0,
            },
            "workflows": [],
            "secret_material_policy": "Prevention exports contain commands and finding IDs only; raw secret material is never included.",
        }

    rows = con.execute(
        """
        SELECT sli.key_finding_id,
               sli.lifecycle_status,
               sli.owner,
               sli.suppressed,
               sli.prevention_guidance_json,
               k.service,
               k.pattern_name
        FROM secret_lifecycle_items sli
        LEFT JOIN key_scanner_findings k
          ON k.engagement_id=sli.engagement_id
         AND k.id=sli.key_finding_id
        WHERE sli.engagement_id=?
        ORDER BY sli.key_finding_id
        """,
        (int(engagement_id),),
    ).fetchall()
    command_index: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    finding_ids: list[int] = []
    suppressed_ids: list[int] = []
    for row in rows:
        key_id = int(row["key_finding_id"] or 0)
        if key_id:
            finding_ids.append(key_id)
        if int(row["suppressed"] or 0):
            suppressed_ids.append(key_id)
        guidance_rows = _json_load(row["prevention_guidance_json"])
        if not isinstance(guidance_rows, list):
            continue
        for guidance in guidance_rows:
            if not isinstance(guidance, Mapping):
                continue
            guidance_workflow = _normalize_prevention_workflow(guidance.get("workflow"))
            if requested_workflow and guidance_workflow != requested_workflow:
                continue
            tool = str(guidance.get("tool") or "").strip()
            command = str(guidance.get("command") or "").strip()
            cost = str(guidance.get("cost") or "").strip()
            if not guidance_workflow or not tool or not command:
                continue
            aggregate = command_index.setdefault(
                (guidance_workflow, tool, command, cost),
                {
                    "workflow": guidance_workflow,
                    "tool": tool,
                    "command": command,
                    "cost": cost,
                    "affected_finding_ids": [],
                    "services": [],
                    "patterns": [],
                    "owners": [],
                    "lifecycle_statuses": [],
                    "suppressed_count": 0,
                },
            )
            aggregate["affected_finding_ids"].append(key_id)
            aggregate["services"].append(_service_key(row["service"]))
            aggregate["patterns"].append(str(row["pattern_name"] or ""))
            aggregate["owners"].append(str(row["owner"] or ""))
            aggregate["lifecycle_statuses"].append(str(row["lifecycle_status"] or ""))
            if int(row["suppressed"] or 0):
                aggregate["suppressed_count"] += 1

    commands = []
    for aggregate in command_index.values():
        item = dict(aggregate)
        item["affected_finding_ids"] = _unique_sorted_ints(item["affected_finding_ids"])
        item["services"] = _unique_sorted_strings(item["services"])
        item["patterns"] = _unique_sorted_strings(item["patterns"])
        item["owners"] = _unique_sorted_strings(item["owners"])
        item["lifecycle_statuses"] = _unique_sorted_strings(item["lifecycle_statuses"])
        commands.append(item)
    commands.sort(key=lambda item: (item["workflow"], item["tool"], item["command"]))

    workflows = []
    for workflow_id, target in _PREVENTION_WORKFLOW_TARGETS.items():
        if requested_workflow and workflow_id != requested_workflow:
            continue
        workflow_commands = [item for item in commands if item["workflow"] == workflow_id]
        if not workflow_commands:
            continue
        workflows.append(
            {
                "workflow": workflow_id,
                "target": dict(target),
                "commands": workflow_commands,
                "artifact_template": _workflow_artifact_template(
                    workflow_id,
                    workflow_commands,
                ),
                "command_count": len(workflow_commands),
                "finding_count": len(
                    {
                        finding_id
                        for item in workflow_commands
                        for finding_id in item["affected_finding_ids"]
                    }
                ),
            }
        )

    return {
        "schema": "forge.secret_prevention.v1",
        "schema_version": "forge.secret_prevention.v1",
        "execution_policy": "plan_only_secret_prevention_no_commands_executed",
        "total_count": len(commands),
        "selected_count": len(commands),
        "omitted_count": 0,
        "engagement_id": int(engagement_id),
        "workflow_filter": requested_workflow or "all",
        "lifecycle_sync": lifecycle_sync,
        "summary": {
            "workflow_count": len(workflows),
            "command_count": len(commands),
            "finding_count": len(_unique_sorted_ints(finding_ids)),
            "suppressed_count": len(_unique_sorted_ints(suppressed_ids)),
        },
        "workflows": workflows,
        "secret_material_policy": "Prevention exports contain commands and finding IDs only; raw secret material is never included.",
    }


def active_suppression_for_secret(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    key_finding_id: int | None = None,
    service: str = "",
    pattern_name: str = "",
    source_url: str = "",
) -> dict[str, Any] | None:
    _ensure_rows(con)
    if not _table_exists(con, "secret_suppressions"):
        return None
    params: list[Any] = [int(engagement_id)]
    where = "engagement_id=? AND status='active' AND (expires_at IS NULL OR expires_at='' OR expires_at > CURRENT_TIMESTAMP)"
    if key_finding_id is not None:
        where += " AND key_finding_id=?"
        params.append(int(key_finding_id))
    else:
        where += " AND service=? AND pattern_name=? AND source_url=?"
        params.extend([service, pattern_name, source_url])
    row = con.execute(
        f"""
        SELECT *
        FROM secret_suppressions
        WHERE {where}
        ORDER BY updated_at DESC, id DESC
        LIMIT 1
        """,
        tuple(params),
    ).fetchone()
    if row is None:
        return None
    payload = dict(row)
    payload["evidence"] = _json_load(payload.pop("evidence_json", "{}"))
    return payload


def create_secret_suppression(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    key_finding_id: int | None,
    reason: str,
    created_by: str = "",
    expires_at: str | None = None,
    evidence: Mapping[str, Any] | None = None,
) -> int:
    _ensure_rows(con)
    row = None
    if key_finding_id is not None and _table_exists(con, "key_scanner_findings"):
        row = con.execute(
            """
            SELECT service, pattern_name, source_url
            FROM key_scanner_findings
            WHERE engagement_id=? AND id=?
            """,
            (int(engagement_id), int(key_finding_id)),
        ).fetchone()
    service = str(row["service"] if row else "")
    pattern_name = str(row["pattern_name"] if row else "")
    source_url = str(row["source_url"] if row else "")
    con.execute(
        """
        INSERT INTO secret_suppressions
            (engagement_id, key_finding_id, service, pattern_name, source_url,
             reason, expires_at, created_by, evidence_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, key_finding_id, service, pattern_name, source_url, status)
        DO UPDATE SET
            reason=excluded.reason,
            expires_at=excluded.expires_at,
            created_by=excluded.created_by,
            evidence_json=excluded.evidence_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            int(engagement_id),
            int(key_finding_id) if key_finding_id is not None else None,
            service,
            pattern_name,
            source_url,
            str(reason or "").strip(),
            expires_at,
            str(created_by or ""),
            _json_dump(dict(evidence or {}), scrub=True),
        ),
    )
    found = active_suppression_for_secret(
        con,
        int(engagement_id),
        key_finding_id=key_finding_id,
    )
    con.commit()
    return int(found["id"]) if found else 0


def _owner_for_key_finding(con: sqlite3.Connection, engagement_id: int, key_id: int) -> tuple[str, str]:
    if not _table_exists(con, "validation_claims"):
        return "", ""
    row = con.execute(
        """
        SELECT owner
        FROM validation_claims
        WHERE engagement_id=?
          AND claim_type='key'
          AND key_id=?
          AND owner IS NOT NULL
          AND TRIM(owner) <> ''
          AND (expires_at IS NULL OR expires_at='' OR expires_at > CURRENT_TIMESTAMP)
        ORDER BY updated_at DESC, id DESC
        LIMIT 1
        """,
        (int(engagement_id), int(key_id)),
    ).fetchone()
    if row:
        return str(row["owner"]), "validation_claims"
    return "", ""


def _secret_remediation_metadata(row: sqlite3.Row, lifecycle_status: str) -> dict[str, Any]:
    return {
        "source": "secret_lifecycle",
        "key_finding_id": int(row["id"]),
        "lifecycle_status": lifecycle_status,
        "service": _service_key(row["service"]),
        "pattern_name": str(row["pattern_name"] or ""),
        "source_backend": str(row["source_backend"] or ""),
        "source_url": str(row["source_url"] or ""),
        "repo_name": str(row["repo_name"] or ""),
        "key_redacted": str(row["key_redacted"] or ""),
        "validation_state": str(row["validation_state"] or ""),
        "validated_at": str(row["validated_at"] or ""),
        "revocation_guidance": revocation_guidance_for_secret(row["service"], row["pattern_name"]),
        "prevention_guidance": prevention_guidance_for_secret(row["service"]),
        "secret_material_policy": "Use the redacted key and key_finding_id only; do not paste raw secret material into remediation records.",
    }


def _upsert_secret_remediation_item(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    row: sqlite3.Row,
    lifecycle_status: str,
    owner: str,
) -> str:
    if not _table_exists(con, "remediation_items"):
        return "skipped"
    key_id = int(row["id"])
    finding_ref = str(key_id)
    existing = con.execute(
        """
        SELECT id, owner, status, metadata_json
        FROM remediation_items
        WHERE engagement_id=? AND finding_table='key_scanner_findings' AND finding_ref=?
        """,
        (int(engagement_id), finding_ref),
    ).fetchone()
    validation_state = str(row["validation_state"] or "").strip().upper()
    if lifecycle_status == "suppressed":
        return "skipped"
    metadata = _secret_remediation_metadata(row, lifecycle_status)
    if existing is not None:
        existing_metadata = _json_load(existing["metadata_json"])
        if isinstance(existing_metadata, dict):
            metadata = {**existing_metadata, **metadata}

    if lifecycle_status == "revoked" or validation_state == "REVOKED":
        if existing is None or str(existing["status"] or "") in _SECRET_REMEDIATION_TERMINAL_STATUSES:
            return "skipped"
        con.execute(
            """
            UPDATE remediation_items
            SET status='resolved',
                retest_status='passed',
                metadata_json=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE engagement_id=? AND id=?
            """,
            (_json_dump(metadata, scrub=True), int(engagement_id), int(existing["id"])),
        )
        return "resolved"

    if validation_state not in {"ACTIVE", "UNCONFIRMED"}:
        return "skipped"

    service = _service_key(row["service"])
    pattern_name = str(row["pattern_name"] or "").strip()
    title_action = "Revoke" if validation_state == "ACTIVE" else "Review"
    title = f"{title_action} exposed {service or 'unknown'} credential"
    if pattern_name:
        title = f"{title}: {pattern_name}"
    severity = "HIGH" if validation_state == "ACTIVE" else "MEDIUM"
    next_owner = str(owner or "").strip()
    next_status = "assigned" if next_owner else "open"
    if existing is None:
        con.execute(
            """
            INSERT INTO remediation_items
                (engagement_id, finding_table, finding_id, finding_ref, title,
                 severity, owner, status, metadata_json)
            VALUES (?, 'key_scanner_findings', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(engagement_id),
                key_id,
                finding_ref,
                title,
                severity,
                next_owner or None,
                next_status,
                _json_dump(metadata, scrub=True),
            ),
        )
        return "created"

    existing_status = str(existing["status"] or "open").strip().lower()
    existing_owner = str(existing["owner"] or "").strip()
    if existing_status in _SECRET_REMEDIATION_TERMINAL_STATUSES:
        return "skipped"
    if existing_owner:
        next_owner = existing_owner
    if existing_status != "open":
        next_status = existing_status
    elif next_owner:
        next_status = "assigned"
    con.execute(
        """
        UPDATE remediation_items
        SET title=?,
            severity=?,
            owner=?,
            status=?,
            metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (
            title,
            severity,
            next_owner or None,
            next_status,
            _json_dump(metadata, scrub=True),
            int(engagement_id),
            int(existing["id"]),
        ),
    )
    return "updated"


def _audit_secret_remediation_action(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    row: sqlite3.Row,
    action: str,
) -> None:
    if action not in {"created", "updated", "resolved"}:
        return
    if not _table_exists(con, "audit_log"):
        return
    service = _service_key(row["service"])
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'secrets', 'secret_lifecycle', 'secret_remediation_sync', ?, ?, 'secret-lifecycle')
        """,
        (
            int(engagement_id),
            f"key_scanner_findings:{int(row['id'])}",
            f"{action} service={service or 'unknown'} state={str(row['validation_state'] or '').strip().upper()}",
        ),
    )


def sync_secret_lifecycle(con: sqlite3.Connection, engagement_id: int) -> dict[str, Any]:
    _ensure_rows(con)
    if not (_table_exists(con, "key_scanner_findings") and _table_exists(con, "secret_lifecycle_items")):
        return {"engagement_id": int(engagement_id), "synced": 0}
    rows = con.execute(
        """
        SELECT id, service, pattern_name, source_backend, source_url,
               repo_name, key_redacted, validation_state, validated_at
        FROM key_scanner_findings
        WHERE engagement_id=?
        """,
        (int(engagement_id),),
    ).fetchall()
    synced = 0
    suppressed_count = 0
    owner_routed_count = 0
    remediation_created_count = 0
    remediation_updated_count = 0
    remediation_resolved_count = 0
    for row in rows:
        key_id = int(row["id"])
        owner, owner_source = _owner_for_key_finding(con, int(engagement_id), key_id)
        suppression = active_suppression_for_secret(con, int(engagement_id), key_finding_id=key_id)
        suppressed = suppression is not None
        if suppressed:
            status = "suppressed"
            suppressed_count += 1
        elif str(row["validation_state"] or "") == "REVOKED":
            status = "revoked"
        elif owner:
            status = "owner_routed"
            owner_routed_count += 1
        else:
            status = "revocation_guided"
        metadata = {
            "source_backend": row["source_backend"],
            "source_url": row["source_url"],
            "repo_name": row["repo_name"],
            "key_redacted": row["key_redacted"],
            "validation_state": row["validation_state"],
            "validated_at": row["validated_at"],
        }
        con.execute(
            """
            INSERT INTO secret_lifecycle_items
                (engagement_id, key_finding_id, lifecycle_status, owner,
                 owner_source, revocation_guidance_json, prevention_guidance_json,
                 suppression_id, suppressed, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, key_finding_id) DO UPDATE SET
                lifecycle_status=excluded.lifecycle_status,
                owner=excluded.owner,
                owner_source=excluded.owner_source,
                revocation_guidance_json=excluded.revocation_guidance_json,
                prevention_guidance_json=excluded.prevention_guidance_json,
                suppression_id=excluded.suppression_id,
                suppressed=excluded.suppressed,
                metadata_json=excluded.metadata_json,
                updated_at=CURRENT_TIMESTAMP
            """,
            (
                int(engagement_id),
                key_id,
                status,
                owner,
                owner_source,
                _json_dump(revocation_guidance_for_secret(row["service"], row["pattern_name"])),
                _json_dump(prevention_guidance_for_secret(row["service"])),
                int(suppression["id"]) if suppression else None,
                1 if suppressed else 0,
                _json_dump(metadata, scrub=True),
            ),
        )
        remediation_action = _upsert_secret_remediation_item(
            con,
            engagement_id=int(engagement_id),
            row=row,
            lifecycle_status=status,
            owner=owner,
        )
        _audit_secret_remediation_action(
            con,
            engagement_id=int(engagement_id),
            row=row,
            action=remediation_action,
        )
        if remediation_action == "created":
            remediation_created_count += 1
        elif remediation_action == "updated":
            remediation_updated_count += 1
        elif remediation_action == "resolved":
            remediation_resolved_count += 1
        synced += 1
    con.commit()
    return {
        "engagement_id": int(engagement_id),
        "synced": synced,
        "suppressed": suppressed_count,
        "owner_routed": owner_routed_count,
        "remediation_created": remediation_created_count,
        "remediation_updated": remediation_updated_count,
        "remediation_resolved": remediation_resolved_count,
    }


def secret_lifecycle_for_finding(
    con: sqlite3.Connection,
    engagement_id: int,
    key_finding_id: int,
) -> dict[str, Any]:
    _ensure_rows(con)
    if not _table_exists(con, "secret_lifecycle_items"):
        return {}
    row = con.execute(
        """
        SELECT *
        FROM secret_lifecycle_items
        WHERE engagement_id=? AND key_finding_id=?
        """,
        (int(engagement_id), int(key_finding_id)),
    ).fetchone()
    if row is None:
        sync_secret_lifecycle(con, int(engagement_id))
        row = con.execute(
            """
            SELECT *
            FROM secret_lifecycle_items
            WHERE engagement_id=? AND key_finding_id=?
            """,
            (int(engagement_id), int(key_finding_id)),
        ).fetchone()
    if row is None:
        return {}
    payload = dict(row)
    payload["revocation_guidance"] = _json_load(payload.pop("revocation_guidance_json", "{}"))
    payload["prevention_guidance"] = _json_load(payload.pop("prevention_guidance_json", "[]"))
    payload["metadata"] = _json_load(payload.pop("metadata_json", "{}"))
    payload["suppressed"] = bool(payload.get("suppressed"))
    return payload
