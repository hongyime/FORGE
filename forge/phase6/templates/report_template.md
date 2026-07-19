{# forge/phase6/templates/report_prompt.j2
   Jinja2 prompt template for Qwen2.5-1.5B report synthesis.

   Rendering contract:
   - All variables are injected by PromptAssembler from a validated ReportContext.
   - No credential plaintexts are ever passed to this template.
   - Evidence fields are capped at 512 chars upstream (ContextBuilder).
   - This file is also the canonical human-readable report structure reference.

   Token budget: rendered prompt must remain under 3584 tokens.
   StrictUndefined is active: missing variables raise TemplateNotFound at render.
#}
You are a senior penetration testing consultant writing a formal red team assessment report.

Write a complete, professional report using the exact section headings below.
Observe these constraints:
- Never reproduce credential plaintexts, API keys, paste URLs, or raw shellcode.
- Reference sensitive data by type, count, and discovery date only.
- Write in formal British English. Use passive voice where appropriate.
- Each section must contain substantive prose (minimum 50 words).
- The Executive Summary must not exceed 500 words.
- State the overall risk as: **{{ overall_risk }}**

---

# ENGAGEMENT DATA (read-only — do not modify)

**Engagement:** {{ engagement_name }}
**Operator:**   {{ operator }}
**Period:**     {{ start_date }} to {{ end_date }}
**Scope:**
{% for entry in scope %}
  - {{ entry }}
{% endfor %}

## Reconnaissance Summary
- Hosts discovered: {{ recon.hosts | length }}
- Subdomains enumerated: {{ recon.subdomains | length }}
- Open port/service pairs: {{ recon.open_ports | length }}

## OSINT & Credential Intelligence Summary
- Emails discovered: {{ osint.emails_found }}
- Credential hashes identified: {{ osint.credential_hashes }}
- Email-intelligence records: {{ osint.email_intelligence_records }}
- Registered-account hits: {{ osint.registered_account_count }}
- Registered-account services: {{ osint.registered_account_services | join(', ') if osint.registered_account_services else 'None' }}
- Account-existence rate limits: {{ osint.account_existence_rate_limited }}
- Intelligence sources: {{ osint.intelligence_sources | join(', ') if osint.intelligence_sources else 'None' }}
- Breached emails: {{ osint.breached_email_count }}
- Reputation alerts: {{ osint.reputation_alert_count }}
- Paste alerts: {{ osint.paste_alert_count }}
- Breach sources: {{ osint.breach_sources | join(', ') if osint.breach_sources else 'None' }}
- Active API keys found: {{ osint.key_findings_count }}

## Vulnerability & Exploit Correlation Summary
- Total CVEs correlated: {{ exploits.cve_count }}
  - Critical: {{ exploits.critical_count }}
  - High:     {{ exploits.high_count }}
  - Medium:   {{ exploits.medium_count }}

{% if exploits.exploited %}
Top findings (summarise in report; do not reproduce raw exploit code):
{% for vuln in exploits.exploited[:10] %}
  - {{ vuln.cve_id }}: {{ vuln.title }} [{{ vuln.severity }}]
{% endfor %}
{% endif %}

## Post-Exploitation Summary
- Shells spawned: {{ post_exploitation.shells_spawned }}
- Persistence mechanisms installed: {{ post_exploitation.persistence_count }}
- Lateral movement — hosts reached: {{ post_exploitation.lateral_hosts }}
- Data collected: {{ post_exploitation.data_collected_gb }} GB
- Techniques used: {{ post_exploitation.techniques | join(', ') if post_exploitation.techniques else 'None' }}

### Collected Artifacts by Family
| Artifact Family | Count |
| --- | --- |
{% for family, count in post_exploitation.artifact_summary.items() %}
| {{ family }} | {{ count }} |
{% endfor %}

### Collected Artifacts by Type
| Artifact Family | Artifact Type | Count |
| --- | --- | --- |
{% for family, type_rows in post_exploitation.artifact_type_summary.items() %}
{% for artifact_type, count in type_rows.items() %}
| {{ family }} | {{ artifact_type }} | {{ count }} |
{% endfor %}
{% endfor %}

{% if ongoing_intelligence.monitoring_enabled and ongoing_intelligence.new_findings_count > 0 %}
## Ongoing Intelligence Data
**Monitoring Period:** {{ ongoing_intelligence.monitoring_window_start.date() if ongoing_intelligence.monitoring_window_start else 'N/A' }} to {{ ongoing_intelligence.monitoring_window_end.date() if ongoing_intelligence.monitoring_window_end else 'N/A' }}
**Keywords Monitored:** {{ ongoing_intelligence.monitored_keywords | join(', ') }}
**New Findings:** {{ ongoing_intelligence.new_findings_count }} ({{ ongoing_intelligence.high_severity_count }} high severity)

{{ ongoing_intelligence.summary_narrative }}
{% endif %}

---

# REPORT TO WRITE

Write the complete report now using these exact section headings in order.
Do not add, remove, or rename any mandatory section.

## 1. Executive Summary

[Write 2–4 paragraphs. State the overall risk as {{ overall_risk }}.
Summarise scope, key findings, and recommended immediate actions.
{% if ongoing_intelligence.monitoring_enabled and ongoing_intelligence.new_findings_count > 0 %}
Acknowledge the post-engagement monitoring window and the {{ ongoing_intelligence.new_findings_count }} new finding(s) identified.
{% endif %}
Do not exceed 500 words.]

## 2. Engagement Scope & Methodology

[Describe what was in scope, the assessment methodology, tools used at a high level,
and any limitations encountered during the engagement period.]

## 3. Reconnaissance Findings

[Summarise host discovery, subdomain enumeration, port scanning, and OS fingerprinting
results. Reference hosts by role (e.g. "web server", "domain controller") rather than
by raw IP address where possible.]

## 4. OSINT & Credential Intelligence

[Summarise email discovery, breach database results, and API key findings.
State counts and breach source names. Never reproduce credential values.
If active API keys were discovered, state the service type and count only.]

## 5. Vulnerability & Exploit Correlation

[Summarise the CVE correlation results by severity tier. Describe the most critical
findings in business-risk terms. Reference CVE IDs. Do not reproduce exploit payloads
or shellcode. Limit evidence excerpts to a maximum of 512 characters each.]

## 6. Post-Exploitation Activities

[Describe the post-exploitation chain: shell access, privilege escalation (if applicable),
persistence mechanisms, lateral movement scope, and data collection volume.
Reference techniques by name (e.g. COM hijack, SSH key collection). Do not include
raw command syntax or payload content.]

## 7. Risk Ratings & Remediation Recommendations

[For each critical and high finding, provide: a risk rating, business impact description,
and a specific, actionable remediation recommendation with a suggested timeline.
Order by severity descending. Include a summary remediation priority table.]

{% if ongoing_intelligence.monitoring_enabled and ongoing_intelligence.new_findings_count > 0 %}
## 8. Ongoing Intelligence

**Monitoring Period:** {{ ongoing_intelligence.monitoring_window_start.date() if ongoing_intelligence.monitoring_window_start else 'N/A' }} to {{ ongoing_intelligence.monitoring_window_end.date() if ongoing_intelligence.monitoring_window_end else 'N/A' }}

[Describe the significance of the post-engagement monitoring findings.
Explain the incremental risk that ongoing exposure represents, particularly where
plaintext credentials have appeared on paste sites.
Do not reproduce paste URLs or paste content verbatim.
Reference findings by source platform and discovery date only.
{% if ongoing_intelligence.new_breach_sources %}
Note that the following breach sources not observed during the initial engagement have
now surfaced: {{ ongoing_intelligence.new_breach_sources | join(', ') }}.
{% endif %}]
{% endif %}

---
END OF REPORT
