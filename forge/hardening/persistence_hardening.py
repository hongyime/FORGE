"""Linper persistence detection and hardening recommendations.

DEFENSIVE ONLY module porting Linper capabilities as Forge automation actions.
This module provides detection checklists, hardening recommendations, and ATT&CK mappings.

OFFENSIVE CAPABILITIES EXCLUDED:
- No persistence installation
- No sudo hijack
- No reverse shell
- No stealth techniques
- No cleanup/anti-forensics

This module is for detection and defensive hardening only.
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class PersistenceCategory(str, Enum):
    """MITRE ATT&CK persistence technique categories."""
    CRON_JOBS = "cron_jobs"
    SYSTEMD_SERVICES = "systemd_services"
    SYSTEMD_TIMERS = "systemd_timers"
    INIT_SCRIPTS = "init_scripts"
    RC_SCRIPTS = "rc_scripts"
    SSH_KEYS = "ssh_keys"
    SUDOERS = "sudoers"
    PAM_MODULES = "pam_modules"
    BASH_PROFILES = "bash_profiles"
    KERNEL_MODULES = "kernel_modules"
    CONTAINERS = "containers"
    APPLICATIONS = "applications"


@dataclass
class PersistenceCheck:
    """Single persistence detection check."""
    category: PersistenceCategory
    location: str
    description: str
    attack_id: str  # MITRE ATT&CK ID
    attack_name: str
    detection_command: str
    indicators: List[str]
    hardening_steps: List[str]
    severity: str  # "critical", "high", "medium", "low"
    platform: str  # "linux", "windows", "both"


# LINPER_PERSISTENCE_CHECKS - Defensive detection matrix
# 12 categories covering common Linux/Unix persistence mechanisms
LINPER_PERSISTENCE_CHECKS: Dict[str, List[PersistenceCheck]] = {
    "cron_jobs": [
        PersistenceCheck(
            category=PersistenceCategory.CRON_JOBS,
            location="/etc/crontab",
            description="System-wide cron table",
            attack_id="T1053.003",
            attack_name="Scheduled Task/Job: Cron",
            detection_command="cat /etc/crontab",
            indicators=[
                "Unusual commands or scripts",
                "Scripts in /tmp or /var/tmp",
                "Encoded/obfuscated commands",
                "Unexpected users",
            ],
            hardening_steps=[
                "Review all entries with cron analysts",
                "Remove unauthorized entries",
                "Set proper permissions (root:root 0600)",
                "Use auditd to monitor changes",
            ],
            severity="high",
            platform="linux",
        ),
        PersistenceCheck(
            category=PersistenceCategory.CRON_JOBS,
            location="/etc/cron.d/",
            description="Cron drop-in directory",
            attack_id="T1053.003",
            attack_name="Scheduled Task/Job: Cron",
            detection_command="ls -la /etc/cron.d/ && cat /etc/cron.d/*",
            indicators=[
                "Unexpected files",
                "Files not owned by root",
                "World-writable files",
                "Suspicious timing patterns",
            ],
            hardening_steps=[
                "Audit all cron.d entries",
                "Restrict write access to root only",
                "Use file integrity monitoring",
            ],
            severity="high",
            platform="linux",
        ),
        PersistenceCheck(
            category=PersistenceCategory.CRON_JOBS,
            location="/var/spool/cron/",
            description="User cron spools",
            attack_id="T1053.003",
            attack_name="Scheduled Task/Job: Cron",
            detection_command="ls -la /var/spool/cron/crontabs/",
            indicators=[
                "Unexpected user crontabs",
                "Modified timestamps",
                "Large file sizes",
            ],
            hardening_steps=[
                "Monitor user crontab creation",
                "Restrict cron access via cron.deny",
            ],
            severity="medium",
            platform="linux",
        ),
    ],
    "systemd_services": [
        PersistenceCheck(
            category=PersistenceCategory.SYSTEMD_SERVICES,
            location="/etc/systemd/system/",
            description="System service units",
            attack_id="T1543.002",
            attack_name="Create or Modify Systemd Service",
            detection_command="find /etc/systemd/system -type f -name '*.service'",
            indicators=[
                "Services with ExecStart to /tmp scripts",
                "Services with User=nobody or unexpected users",
                "Services with overly permissive capabilities",
                "Services with Restart=always and short intervals",
            ],
            hardening_steps=[
                "Review all custom services",
                "Remove unauthorized services",
                "Set proper permissions (root:root 0644)",
                "Use systemd-analyze verify",
            ],
            severity="critical",
            platform="linux",
        ),
        PersistenceCheck(
            category=PersistenceCategory.SYSTEMD_SERVICES,
            location="/lib/systemd/system/",
            description="Distribution service units (rarely modified)",
            attack_id="T1543.002",
            attack_name="Create or Modify Systemd Service",
            detection_command="find /lib/systemd/system -type f -name '*.service' -mtime -30",
            indicators=[
                "Recently modified system services",
                "Changes to core services",
            ],
            hardening_steps=[
                "Compare with package manager versions",
                "Use file integrity monitoring",
            ],
            severity="critical",
            platform="linux",
        ),
    ],
    "systemd_timers": [
        PersistenceCheck(
            category=PersistenceCategory.SYSTEMD_TIMERS,
            location="/etc/systemd/system/*.timer",
            description="Systemd timer units",
            attack_id="T1543.002",
            attack_name="Create or Modify Systemd Service",
            detection_command="find /etc/systemd/system -type f -name '*.timer'",
            indicators=[
                "Unexpected timer units",
                "Timers triggering suspicious services",
                "Short intervals combined with restart services",
            ],
            hardening_steps=[
                "List all timers: systemctl list-timers",
                "Disable unauthorized timers",
                "Monitor timer creation",
            ],
            severity="high",
            platform="linux",
        ),
    ],
    "init_scripts": [
        PersistenceCheck(
            category=PersistenceCategory.INIT_SCRIPTS,
            location="/etc/init.d/",
            description="SysV init scripts",
            attack_id="T1053.003",
            attack_name="Scheduled Task/Job: Cron",
            detection_command="ls -la /etc/init.d/",
            indicators=[
                "Unexpected scripts",
                "Modified existing scripts",
                "Scripts with suspicious commands",
            ],
            hardening_steps=[
                "Audit all init.d scripts",
                "Remove unauthorized scripts",
                "Use file integrity monitoring",
            ],
            severity="high",
            platform="linux",
        ),
    ],
    "rc_scripts": [
        PersistenceCheck(
            category=PersistenceCategory.RC_SCRIPTS,
            location="/etc/rc.local",
            description="Boot-time execution script",
            attack_id="T1053.003",
            attack_name="Scheduled Task/Job: Cron",
            detection_command="cat /etc/rc.local 2>/dev/null || echo 'File not present'",
            indicators=[
                "Unexpected commands",
                "Script execution from unusual locations",
                "Backgrounded processes",
            ],
            hardening_steps=[
                "Review rc.local contents",
                "Set proper permissions",
                "Consider disabling if unused",
            ],
            severity="high",
            platform="linux",
        ),
    ],
    "ssh_keys": [
        PersistenceCheck(
            category=PersistenceCategory.SSH_KEYS,
            location="~/.ssh/authorized_keys",
            description="SSH authorized keys",
            attack_id="T1098.004",
            attack_name="Valid Accounts: SSH Authorized Keys",
            detection_command="find /home -name 'authorized_keys' -exec ls -la {} \\;",
            indicators=[
                "Unexpected keys",
                "Keys with unusual permissions",
                "Keys added recently",
                "Keys for disabled accounts",
            ],
            hardening_steps=[
                "Audit all authorized_keys files",
                "Remove unauthorized keys",
                "Use SSH certificates instead of keys",
                "Restrict SSH key types",
            ],
            severity="critical",
            platform="linux",
        ),
        PersistenceCheck(
            category=PersistenceCategory.SSH_KEYS,
            location="/root/.ssh/authorized_keys",
            description="Root SSH authorized keys",
            attack_id="T1098.004",
            attack_name="Valid Accounts: SSH Authorized Keys",
            detection_command="cat /root/.ssh/authorized_keys 2>/dev/null || echo 'File not present'",
            indicators=[
                "Any keys present (should be rare)",
                "Keys without command restrictions",
                "Keys without from restrictions",
            ],
            hardening_steps=[
                "Disable root SSH login (PermitRootLogin no)",
                "Remove all root authorized_keys if possible",
                "Use sudo instead of root SSH",
            ],
            severity="critical",
            platform="linux",
        ),
    ],
    "sudoers": [
        PersistenceCheck(
            category=PersistenceCategory.SUDOERS,
            location="/etc/sudoers",
            description="Sudo configuration",
            attack_id="T1548.003",
            attack_name="Abuse Elevation Control Mechanism: Sudo",
            detection_command="cat /etc/sudoers",
            indicators=[
                "NOPASSWD entries",
                "Wildcards (*) in commands",
                "Scripts in /tmp or user directories",
                "Unusual user/role grants",
            ],
            hardening_steps=[
                "Use visudo to edit",
                "Remove NOPASSWD where possible",
                "Avoid wildcards",
                "Use command arguments explicitly",
            ],
            severity="critical",
            platform="linux",
        ),
        PersistenceCheck(
            category=PersistenceCategory.SUDOERS,
            location="/etc/sudoers.d/",
            description="Sudo drop-in directory",
            attack_id="T1548.003",
            attack_name="Abuse Elevation Control Mechanism: Sudo",
            detection_command="ls -la /etc/sudoers.d/ && cat /etc/sudoers.d/*",
            indicators=[
                "Unexpected files",
                "Files not owned by root",
                "World-readable files",
            ],
            hardening_steps=[
                "Audit every sudoers.d file",
                "Set permissions to 0440",
                "Use visudo -f for verification",
            ],
            severity="critical",
            platform="linux",
        ),
    ],
    "pam_modules": [
        PersistenceCheck(
            category=PersistenceCategory.PAM_MODULES,
            location="/etc/pam.d/",
            description="PAM configuration",
            attack_id="T1547.002",
            attack_name="Boot or Logon Autostart Execution: Authentication Package",
            detection_command="ls -la /etc/pam.d/",
            indicators=[
                "Unexpected pam_ modules",
                "pam_exec calling scripts",
                "Modified timestamps",
                "Unusual module ordering",
            ],
            hardening_steps=[
                "Review all PAM configs",
                "Remove unauthorized modules",
                "Use file integrity monitoring",
                "Compare with package versions",
            ],
            severity="critical",
            platform="linux",
        ),
    ],
    "bash_profiles": [
        PersistenceCheck(
            category=PersistenceCategory.BASH_PROFILES,
            location="~/.bashrc, ~/.bash_profile, ~/.profile",
            description="Shell initialization scripts",
            attack_id="T1053.003",
            attack_name="Scheduled Task/Job: Cron",
            detection_command="find /home -name '.bashrc' -o -name '.bash_profile' -o -name '.profile' | xargs grep -l 'exec\\|source\\|eval'",
            indicators=[
                "Suspicious commands in profile files",
                "Automatic execution of binaries",
                "Backgrounded commands",
                "Encoded strings",
            ],
            hardening_steps=[
                "Audit all user profile files",
                "Remove suspicious entries",
                "Check for keylogging or reverse shells",
            ],
            severity="medium",
            platform="linux",
        ),
    ],
    "kernel_modules": [
        PersistenceCheck(
            category=PersistenceCategory.KERNEL_MODULES,
            location="/etc/modules-load.d/",
            description="Kernel module autoload configuration",
            attack_id="T1547.006",
            attack_name="Boot or Logon Autostart Execution: Kernel Modules and Extensions",
            detection_command="ls -la /etc/modules-load.d/",
            indicators=[
                "Unexpected .conf files",
                "Modules outside standard set",
                "Recently modified files",
            ],
            hardening_steps=[
                "Audit all modules-load entries",
                "Remove unauthorized modules",
                "Use file integrity monitoring",
            ],
            severity="critical",
            platform="linux",
        ),
        PersistenceCheck(
            category=PersistenceCategory.KERNEL_MODULES,
            location="/lib/modules/*/modules.dep",
            description="Kernel module dependencies",
            attack_id="T1547.006",
            attack_name="Boot or Logon Autostart Execution: Kernel Modules and Extensions",
            detection_command="lsmod",
            indicators=[
                "Unexpected loaded modules",
                "Rootkit-like modules",
            ],
            hardening_steps=[
                "Compare loaded modules against baseline",
                "Blacklist unnecessary modules",
            ],
            severity="high",
            platform="linux",
        ),
    ],
    "containers": [
        PersistenceCheck(
            category=PersistenceCategory.CONTAINERS,
            location="/var/lib/docker/containers/",
            description="Docker container configurations",
            attack_id="T1610",
            attack_name="Deploy Container",
            detection_command="docker ps -a 2>/dev/null || echo 'Docker not available'",
            indicators=[
                "Unexpected containers",
                "Containers with privileged mode",
                "Containers mounting host filesystem",
                "Containers with host network",
            ],
            hardening_steps=[
                "Audit all running containers",
                "Remove unnecessary containers",
                "Avoid privileged containers",
                "Use read-only mounts where possible",
            ],
            severity="high",
            platform="linux",
        ),
    ],
    "applications": [
        PersistenceCheck(
            category=PersistenceCategory.APPLICATIONS,
            location="/usr/local/bin/, /opt/",
            description="Custom application installations",
            attack_id="T1547",
            attack_name="Boot or Logon Autostart Execution",
            detection_command="find /usr/local/bin -type f -perm -111; find /opt -type f -perm -111",
            indicators=[
                "Unexpected executables",
                "Binaries not from package manager",
                "Scripts with suspicious content",
            ],
            hardening_steps=[
                "Audit custom installations",
                "Verify integrity of binaries",
                "Use package manager when possible",
            ],
            severity="medium",
            platform="linux",
        ),
    ],
}


def detect_persistence_indicators(
    category: Optional[PersistenceCategory] = None,
    platform: str = "linux"
) -> Dict[str, Any]:
    """Generate persistence detection checklist for automation.
    
    DEFENSIVE ONLY - returns detection commands and indicators for review.
    Does NOT execute any commands or modify any system state.
    
    Args:
        category: Optional specific category to check. If None, returns all.
        platform: Platform to check (linux, windows, both).
    
    Returns:
        Dict with categories, checks, detection commands, and hardening steps.
    """
    result = {
        "schema_version": "forge.hardening.persistence_detection.v1",
        "mode": "defensive_only",
        "platform": platform,
        "categories": {},
        "summary": {
            "total_checks": 0,
            "critical_checks": 0,
            "high_checks": 0,
            "medium_checks": 0,
            "low_checks": 0,
        }
    }
    
    categories_to_check = [category.value] if category else list(LINPER_PERSISTENCE_CHECKS.keys())
    
    for cat_name in categories_to_check:
        if cat_name not in LINPER_PERSISTENCE_CHECKS:
            continue
            
        checks = LINPER_PERSISTENCE_CHECKS[cat_name]
        filtered_checks = [
            c for c in checks
            if c.platform == platform or c.platform == "both"
        ]
        
        if not filtered_checks:
            continue
            
        result["categories"][cat_name] = {
            "attack_id": filtered_checks[0].attack_id,
            "attack_name": filtered_checks[0].attack_name,
            "checks": [
                {
                    "location": c.location,
                    "description": c.description,
                    "detection_command": c.detection_command,
                    "indicators": c.indicators,
                    "hardening_steps": c.hardening_steps,
                    "severity": c.severity,
                }
                for c in filtered_checks
            ]
        }
        
        for c in filtered_checks:
            result["summary"]["total_checks"] += 1
            if c.severity == "critical":
                result["summary"]["critical_checks"] += 1
            elif c.severity == "high":
                result["summary"]["high_checks"] += 1
            elif c.severity == "medium":
                result["summary"]["medium_checks"] += 1
            else:
                result["summary"]["low_checks"] += 1
    
    return result


def generate_harden_report(engagement_id: int) -> Dict[str, Any]:
    """Generate hardening recommendations report for an engagement.
    
    DEFENSIVE ONLY - provides recommendations, does NOT implement changes.
    
    Args:
        engagement_id: Engagement ID to scope the report.
    
    Returns:
        Dict with hardening recommendations categorized by severity.
    """
    return {
        "schema_version": "forge.hardening.harden_report.v1",
        "engagement_id": engagement_id,
        "mode": "defensive_recommendations_only",
        "generated_at": None,  # Filled by caller with datetime
        "categories": detect_persistence_indicators(),
        "next_actions": [
            "Review detection_command outputs",
            "Document findings in engagement notes",
            "Prioritize critical and high severity items",
            "Create remediation items for identified persistence",
            "Schedule retest after hardening",
        ]
    }
