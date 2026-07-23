from __future__ import annotations

import os
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any


PrerequisiteRecord = dict[str, object]

_MOBILE_ARTIFACT_PATTERNS = ("*.apk", "*.aab", "*.xapk", "*.apkm", "*.apks", "*.ipa")


def detect_kill_chain_prerequisites(
    *,
    db_path: Path,
    engagement_id: int,
    engagement: str,
    domain: str,
    include_offensive_prereqs: bool,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> list[PrerequisiteRecord]:
    """Return safe runnable prereqs plus optional manual-only offensive hints."""
    effective_env = env or os.environ
    effective_cwd = cwd or Path.cwd()
    detected: list[PrerequisiteRecord] = []

    def add(
        label: str,
        reason: str,
        *,
        argv: list[str] | None = None,
        manual_hint: str | None = None,
    ) -> None:
        detected.append(
            {
                "label": label,
                "reason": reason,
                "argv": argv,
                "manual_hint": manual_hint,
                "runnable": argv is not None,
            }
        )

    _add_safe_prereqs(detected, add, engagement=engagement, domain=domain, cwd=effective_cwd, env=effective_env)
    if include_offensive_prereqs:
        _add_offensive_prereqs(
            detected,
            add,
            db_path=db_path,
            engagement_id=engagement_id,
            engagement=engagement,
            env=effective_env,
        )
    return detected


def _add_safe_prereqs(
    _detected: list[PrerequisiteRecord],
    add: Any,
    *,
    engagement: str,
    domain: str,
    cwd: Path,
    env: Mapping[str, str],
) -> None:
    if env.get("FORGE_DEHASHED_API_KEY") and env.get("FORGE_DEHASHED_EMAIL"):
        add(
            "osint dehashed (Module 2-C)",
            "FORGE_DEHASHED_* env vars are set",
            argv=[
                "osint",
                "dehashed",
                "--engagement",
                engagement,
                "--query-type",
                "domain",
                "--query-value",
                domain,
            ],
        )

    breach_dir = cwd / ".forge_data" / "breach"
    if breach_dir.is_dir():
        dumps = [path for path in breach_dir.glob("*") if path.is_file()]
        if dumps:
            add(
                "osint breach (Module 2-A)",
                f"{len(dumps)} breach dump(s) in .forge_data/breach/",
                argv=["osint", "breach", "--engagement", engagement, "--db", str(dumps[0])],
            )

    if env.get("AWS_PROFILE") or env.get("AWS_ACCESS_KEY_ID"):
        add(
            "cloud aws (Module 4)",
            "AWS creds detected in env",
            argv=["cloud", "aws", "--engagement", engagement],
        )

    if env.get("FORGE_AZURE_SUBSCRIPTION_ID") or env.get("AZURE_TENANT_ID"):
        add(
            "cloud azure (Module 4)",
            "Azure creds detected in env",
            argv=["cloud", "azure", "--engagement", engagement],
        )

    mobile_artifacts = _local_mobile_artifacts(cwd)
    if mobile_artifacts:
        from forge.engagement_orchestrator import default_local_artifact_roots

        local_artifact_roots = [path for path in default_local_artifact_roots(cwd) if path.is_dir()]
        visible_roots = ", ".join(path.as_posix() for path in local_artifact_roots[:4])
        add(
            "cloud firebase-extract (Module 4-F)",
            f"{len(mobile_artifacts)} mobile package(s) across {visible_roots}",
            argv=[
                "cloud",
                "firebase-extract",
                "--engagement",
                engagement,
                "--apk",
                str(mobile_artifacts[0]),
            ],
        )


def _local_mobile_artifacts(cwd: Path) -> list[Path]:
    from forge.engagement_orchestrator import default_local_artifact_roots

    artifacts: list[Path] = []
    for artifact_root in (path for path in default_local_artifact_roots(cwd) if path.is_dir()):
        for pattern in _MOBILE_ARTIFACT_PATTERNS:
            artifacts.extend(path for path in artifact_root.glob(pattern) if path.is_file())
    return artifacts


def _add_offensive_prereqs(
    _detected: list[PrerequisiteRecord],
    add: Any,
    *,
    db_path: Path,
    engagement_id: int,
    engagement: str,
    env: Mapping[str, str],
) -> None:
    if str(env.get("FORGE_SAFE_MODE", "0")).strip() in ("0", "false", "no", ""):
        add(
            "evasion generate (Phase 3)",
            "FORGE_SAFE_MODE is off - payload generation available",
            manual_hint=(
                f"forge evasion generate --engagement {engagement} "
                "--technique <lolbin-technique> --os windows"
            ),
        )

    service_count = _optional_count(
        db_path,
        """
        SELECT COUNT(*) FROM services s JOIN hosts h ON s.host_id=h.id
        WHERE h.engagement_id=?
        """,
        (engagement_id,),
    )
    credential_count = _optional_count(
        db_path,
        "SELECT COUNT(*) FROM credentials WHERE engagement_id=?",
        (engagement_id,),
    )
    if service_count > 0:
        add(
            "vuln idor (Module 4-D)",
            f"{service_count} discovered service(s) - IDOR probing available",
            manual_hint=f"forge vuln idor --engagement {engagement} --target-url <url>",
        )
    if service_count > 0 and credential_count > 0:
        add(
            "auth brute (Phase 4)",
            f"{service_count} service(s) + {credential_count} credential(s) - brute-force ready",
            manual_hint=f"forge auth brute --engagement {engagement} --target <host> --service <svc>",
        )
    if service_count > 0:
        add(
            "auth bypass (Phase 4)",
            f"{service_count} service(s) with potential auth surfaces",
            manual_hint=f"forge auth bypass --engagement {engagement} --target-url <url>",
        )

    validated_count = _optional_count(
        db_path,
        "SELECT COUNT(*) FROM credentials WHERE engagement_id=? AND validated=1",
        (engagement_id,),
        default_on_error=0,
    )
    if validated_count > 0:
        add(
            "post {shell,beacon,lateral} (Phase 5)",
            f"{validated_count} VALIDATED credential(s) - post-ex viable "
            "(requires FORGE_SAFE_MODE=0 + written ROE)",
            manual_hint=(
                f"forge post shell --engagement {engagement} "
                "--target <host> --service ssh --cred-id <id>"
            ),
        )


def _optional_count(
    db_path: Path,
    sql: str,
    params: tuple[object, ...],
    *,
    default_on_error: int = 0,
) -> int:
    try:
        con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            return int((con.execute(sql, params).fetchone() or [default_on_error])[0] or 0)
        except sqlite3.OperationalError:
            return default_on_error
        finally:
            con.close()
    except Exception:  # noqa: BLE001
        return default_on_error
