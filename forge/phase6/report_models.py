"""Low-level report model shared by synthesis and validation."""

from dataclasses import dataclass, field
from datetime import datetime

MANDATORY_SECTIONS = [
    "## 1. Executive Summary",
    "## 2. Engagement Scope & Methodology",
    "## 3. Reconnaissance Findings",
    "## 4. OSINT & Credential Intelligence",
    "## 5. Vulnerability & Exposure Correlation",
    "## 6. Validation Boundaries & Evidence Handling",
    "## 7. Risk Ratings & Remediation Recommendations",
]

@dataclass
class OngoingIntelligenceContext:
    monitoring_enabled: bool = False
    monitored_keywords: list[str] = field(default_factory=list)
    monitoring_window_start: datetime | None = None
    monitoring_window_end: datetime | None = None
    new_findings_count: int = 0
    high_severity_count: int = 0
    new_breach_sources: list[str] = field(default_factory=list)
    summary_narrative: str = ""
