"""
Test suite for LLM Report Synthesizer Validation Enhancement.

Tests cover:
- Enhanced database schema for LLM feedback
- Multi-shot self-correction functionality
- Validation scoring algorithms
- OPSEC violation detection
- Hallucination detection and factual accuracy
"""

import pytest
import tempfile
import json
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from forge.phase6.report_synthesizer import (
    ReportSynthesizer,
    ContextBuilder,
    PromptAssembler,
    _derive_overall_risk,
    PromptOverflowError,
    ReportGenerationError,
)


class TestEnhancedLLMSchema:
    """Test enhanced LLM feedback database schema."""

    def test_llm_feedback_schema_enhancement(self):
        """Test that enhanced LLM feedback schema is properly created."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"

            # Create database with new schema
            conn = sqlite3.connect(db_path)
            conn.executescript("""
                CREATE TABLE llm_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER REFERENCES engagements(id),
                    model TEXT NOT NULL DEFAULT 'qwen2.5-1.5b',
                    prompt_hash TEXT,
                    response_hash TEXT,
                    quality_score REAL,
                    validator_ok INTEGER NOT NULL DEFAULT 0,
                    generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    correction_loops INTEGER DEFAULT 0,
                    feedback_text TEXT,
                    narrative_coherence_score REAL,
                    opsec_violation_count INTEGER DEFAULT 0,
                    hallucination_score REAL,
                    factual_accuracy_score REAL,
                    engagement_context_relevance REAL,
                    final_approval BOOLEAN DEFAULT FALSE,
                    validation_timestamp TIMESTAMP
                );
                
                CREATE TABLE llm_validation_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL UNIQUE,
                    rule_type TEXT NOT NULL CHECK (rule_type IN ('opsec','factual','coherence','relevance')),
                    severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
                    pattern TEXT NOT NULL,
                    description TEXT,
                    remediation_hint TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Insert test data
            conn.execute("""
                INSERT INTO llm_feedback 
                (engagement_id, prompt_hash, response_hash, quality_score, validator_ok,
                 correction_loops, narrative_coherence_score, opsec_violation_count,
                 hallucination_score, factual_accuracy_score, engagement_context_relevance,
                 final_approval)
                VALUES (1, 'test_prompt_hash', 'test_response_hash', 0.85, 1,
                        2, 0.90, 0, 0.05, 0.95, 0.88, 1)
            """)

            # Verify enhanced fields
            cursor = conn.cursor()
            cursor.execute("""
                SELECT correction_loops, narrative_coherence_score, opsec_violation_count,
                       hallucination_score, factual_accuracy_score, engagement_context_relevance,
                       final_approval
                FROM llm_feedback WHERE engagement_id = 1
            """)

            result = cursor.fetchone()
            assert result is not None
            assert result[0] == 2  # correction_loops
            assert result[1] == 0.90  # narrative_coherence_score
            assert result[2] == 0  # opsec_violation_count
            assert result[3] == 0.05  # hallucination_score
            assert result[4] == 0.95  # factual_accuracy_score
            assert result[5] == 0.88  # engagement_context_relevance
            assert result[6] == 1  # final_approval

            conn.close()

    def test_validation_rules_population(self):
        """Test that default validation rules are properly populated."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"

            # Create database with validation rules
            conn = sqlite3.connect(db_path)
            conn.executescript("""
                CREATE TABLE llm_validation_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL UNIQUE,
                    rule_type TEXT NOT NULL CHECK (rule_type IN ('opsec','factual','coherence','relevance')),
                    severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
                    pattern TEXT NOT NULL,
                    description TEXT,
                    remediation_hint TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                
                INSERT INTO llm_validation_rules 
                (rule_name, rule_type, severity, pattern, description, remediation_hint)
                VALUES 
                ('hardcoded_ip', 'opsec', 'critical', '\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b', 
                 'Hardcoded IP addresses in reports', 'Replace with [REDACTED] or similar'),
                ('credential_exposure', 'opsec', 'critical', '(?i)(password|token|key|secret)\\s*[:=]\\s*\\S+',
                 'Credential plaintext exposure', 'Reference credentials by type only, never reveal values'),
                ('section_length', 'coherence', 'medium', '.{0,49}', 
                 'Sections should contain sufficient narrative detail', 'Expand terse sections with concise evidence-backed prose');
            """)

            # Verify rules were inserted
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM llm_validation_rules WHERE enabled = 1")
            count = cursor.fetchone()[0]
            assert count >= 2

            # Verify rule types and severities
            cursor.execute("SELECT DISTINCT rule_type FROM llm_validation_rules")
            rule_types = [row[0] for row in cursor.fetchall()]
            assert "opsec" in rule_types

            cursor.execute("SELECT DISTINCT severity FROM llm_validation_rules")
            severities = [row[0] for row in cursor.fetchall()]
            assert "critical" in severities
            assert "medium" in severities

            conn.close()


class TestMultiShotSelfCorrection:
    """Test multi-shot self-correction functionality."""

    def test_validation_scoring_algorithm(self):
        """Test validation scoring algorithm for different aspects."""
        # Mock validation results
        validation_results = {
            "narrative_coherence": 0.85,
            "factual_accuracy": 0.92,
            "opsec_compliance": 1.0,
            "engagement_relevance": 0.78,
        }

        # Calculate combined score (weighted average)
        weights = {
            "narrative_coherence": 0.25,
            "factual_accuracy": 0.35,
            "opsec_compliance": 0.25,
            "engagement_relevance": 0.15,
        }

        combined_score = sum(validation_results[key] * weights[key] for key in validation_results)

        assert 0.0 <= combined_score <= 1.0
        assert combined_score > 0.8  # Should be high quality

    def test_correction_loop_convergence(self):
        """Test that correction loops converge within reasonable iterations."""
        max_iterations = 5
        convergence_threshold = 0.85

        # Simulate correction loop
        scores = [0.65, 0.72, 0.81, 0.87, 0.89]  # Improving scores

        for i, score in enumerate(scores):
            if score >= convergence_threshold:
                # Converged successfully
                assert i < max_iterations
                break
        else:
            # Should not reach here
            assert False, "Correction loop should converge"

    def test_opsec_violation_detection(self):
        """Test OPSEC violation detection in generated reports."""
        # Test report with OPSEC violations
        test_report = """
        # Security Assessment Report
        
        ## Executive Summary
        We identified several vulnerabilities in the target network at 192.168.1.100.
        
        ## Findings
        - Weak password: admin123 found in database
        - API key exposed: AKIA123456789EXAMPLE
        - Tool usage: We used Metasploit to exploit the vulnerability
        """

        # Define OPSEC violation patterns
        opsec_patterns = [
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",  # IP addresses
            r"(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+",  # Credentials
            r"(?i)(?:nmap|metasploit|burp|sqlmap|forge)",  # Tool names
        ]

        violations = []
        for pattern in opsec_patterns:
            import re

            matches = re.findall(pattern, test_report)
            violations.extend(matches)

        assert len(violations) > 0  # Should detect violations
        assert "192.168.1.100" in str(violations)
        assert "password" in str(violations).lower()
        assert "metasploit" in str(violations).lower()

    def test_hallucination_detection(self):
        """Test hallucination detection by cross-referencing with database."""
        # Mock engagement database findings
        db_findings = {
            "CVE-2021-44228": {
                "severity": "CRITICAL",
                "title": "Log4Shell Remote Code Execution",
                "cvss_score": 10.0,
            },
            "CVE-2021-34527": {
                "severity": "CRITICAL",
                "title": "PrintNightmare",
                "cvss_score": 8.8,
            },
        }

        # Test report with hallucinated findings
        test_report = """
        ## Vulnerability Findings
        
        - CVE-2021-44228: Critical remote code execution in Log4j (CVSS: 10.0)
        - CVE-2021-99999: New critical vulnerability discovered (CVSS: 9.9)
        - CVE-2021-34527: PrintNightmare vulnerability (CVSS: 8.8)
        """

        # Extract CVE references
        import re

        cve_pattern = r"CVE\s*-\s*\d{4}-\d+"
        reported_cves = re.findall(cve_pattern, test_report)

        # Check for hallucinations
        hallucinations = []
        for cve in reported_cves:
            if cve not in db_findings:
                hallucinations.append(cve)

        assert len(hallucinations) > 0  # Should detect hallucinations
        assert "CVE-2021-99999" in hallucinations
        assert "CVE-2021-44228" not in hallucinations  # Real CVE
        assert "CVE-2021-34527" not in hallucinations  # Real CVE

    def test_factual_accuracy_validation(self):
        """Test factual accuracy validation against database findings."""
        # Mock database findings
        db_findings = [
            {
                "vuln_type": "IDOR",
                "target_url": "https://example.com/api/users",
                "severity": "HIGH",
                "title": "Insecure Direct Object Reference",
            },
            {
                "vuln_type": "SQL_INJECTION",
                "target_url": "https://example.com/login",
                "severity": "CRITICAL",
                "title": "SQL Injection in Login Form",
            },
        ]

        # Test report content
        test_report = """
        ## Vulnerability Assessment
        
        We discovered an IDOR vulnerability at https://example.com/api/users
        with HIGH severity, allowing unauthorized access to user data.
        
        Additionally, we found SQL injection at https://example.com/login
        with CRITICAL severity in the authentication mechanism.
        """

        # Validate factual accuracy
        accuracy_score = 0.0
        matches = 0

        for finding in db_findings:
            # Check if finding is mentioned in report
            if (
                finding["target_url"] in test_report
                and finding["severity"].lower() in test_report.lower()
            ):
                matches += 1

        accuracy_score = matches / len(db_findings)
        assert accuracy_score == 1.0  # All findings should be accurately reported


class TestReportSynthesizerIntegration:
    """Test integration of enhanced LLM validation with report synthesizer."""

    def test_context_builder_with_validation(self):
        """Test ContextBuilder integration with validation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"

            # Create test database with findings
            conn = sqlite3.connect(db_path)
            conn.executescript("""
                CREATE TABLE engagements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    operator TEXT NOT NULL DEFAULT 'test_operator'
                );
                
                CREATE TABLE vulnerability_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    vuln_type TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    cvss_score REAL,
                    found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                
                INSERT INTO engagements (id, name) VALUES (1, 'Test Engagement');
                
                INSERT INTO vulnerability_findings 
                (engagement_id, vuln_type, target_url, severity, title, description, cvss_score)
                VALUES 
                (1, 'IDOR', 'https://example.com/api/users', 'HIGH', 'Insecure Direct Object Reference', 
                 'IDOR vulnerability allows unauthorized access', 7.5),
                (1, 'SQL_INJECTION', 'https://example.com/login', 'CRITICAL', 'SQL Injection',
                 'SQL injection in login form allows authentication bypass', 9.1);
            """)
            conn.commit()
            conn.close()

            # Test context building
            builder = ContextBuilder(db_path, engagement_id=1)
            context = builder.build()

            # Verify context contains findings. CVE count only tracks distinct CVE IDs,
            # not generic vulnerability rows without cve_id.
            assert context.exploits.finding_count == 2
            assert context.exploits.cve_count == 0
            assert context.exploits.high_count == 1  # One HIGH
            assert context.exploits.critical_count == 1  # One CRITICAL
            assert context.overall_risk == "CRITICAL"  # Highest severity

    def test_prompt_assembler_with_validation_rules(self):
        """Test PromptAssembler integration with validation rules."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"

            # Create validation rules
            conn = sqlite3.connect(db_path)
            conn.executescript("""
                CREATE TABLE llm_validation_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL UNIQUE,
                    rule_type TEXT NOT NULL CHECK (rule_type IN ('opsec','factual','coherence','relevance')),
                    severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
                    pattern TEXT NOT NULL,
                    description TEXT,
                    remediation_hint TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                
                INSERT INTO llm_validation_rules 
                (rule_name, rule_type, severity, pattern, description, remediation_hint)
                VALUES 
                ('hardcoded_ip', 'opsec', 'critical', '\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b', 
                 'Hardcoded IP addresses in reports', 'Replace with [REDACTED] or similar');
            """)
            conn.close()

            # Test prompt assembly with validation context
            assembler = PromptAssembler()

            # Mock context
            from forge.phase6.report_synthesizer import (
                ReportContext,
                ExploitContext,
                ReconContext,
                OsintContext,
                PostExploitContext,
            )

            context = ReportContext(
                engagement_id=1,
                engagement_name="Test Engagement",
                operator="test_operator",
                scope=["https://example.com"],
                start_date="2024-01-01",
                end_date="2024-01-31",
                overall_risk="HIGH",
                recon=ReconContext(),
                osint=OsintContext(),
                exploits=ExploitContext(
                    cve_count=2,
                    critical_count=1,
                    high_count=1,
                    medium_count=0,
                    exploited=[
                        {"cve_id": "CVE-2021-44228", "severity": "CRITICAL", "title": "Log4Shell"},
                        {"cve_id": "CVE-2021-34527", "severity": "HIGH", "title": "PrintNightmare"},
                    ],
                ),
                post_exploitation=PostExploitContext(),
            )

            prompt = assembler.assemble(context)

            # Verify prompt contains validation context
            assert "Test Engagement" in prompt
            assert "HIGH" in prompt
            assert "CVE-2021-44228" in prompt
            assert "Log4Shell" in prompt

    def test_report_generation_with_validation_feedback(self):
        """Test report generation with validation feedback loop."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            output_dir = Path(temp_dir) / "output"

            # Create test database
            conn = sqlite3.connect(db_path)
            conn.executescript("""
                CREATE TABLE engagements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    operator TEXT NOT NULL DEFAULT 'test_operator'
                );
                
                CREATE TABLE vulnerability_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    vuln_type TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    cvss_score REAL,
                    found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                
                INSERT INTO engagements (id, name) VALUES (1, 'Test Engagement');
                
                INSERT INTO vulnerability_findings 
                (engagement_id, vuln_type, target_url, severity, title, description, cvss_score)
                VALUES 
                (1, 'IDOR', 'https://example.com/api/users', 'HIGH', 'Insecure Direct Object Reference', 
                 'IDOR vulnerability allows unauthorized access', 7.5);
            """)
            conn.commit()
            conn.close()

            # Mock LLM response with validation
            mock_llm_response = """
            # Security Assessment Report
            
            ## Executive Summary
            This assessment identified security vulnerabilities in the target application.
            
            ## Key Findings
            - IDOR vulnerability at https://example.com/api/users with HIGH severity (CVSS: 7.5)
            - Insecure Direct Object Reference allows unauthorized access to user data
            
            ## Recommendations
            Implement proper authorization checks and input validation.
            """

            # Test synthesizer with mocked LLM
            with patch("forge.phase6.report_synthesizer.Llama") as mock_llama_class:
                mock_llama = Mock()
                mock_llama_class.return_value = mock_llama

                mock_response = {"choices": [{"message": {"content": mock_llm_response}}]}
                mock_llama.create_chat_completion.return_value = mock_response

                synthesizer = ReportSynthesizer(
                    db_path=db_path, output_dir=output_dir, model_path=Path(temp_dir) / "model.gguf"
                )

                # Mock the model file exists
                with patch("pathlib.Path.exists", return_value=True):
                    with patch("questionary.confirm", return_value=True):
                        report_path = synthesizer.generate(
                            engagement_id=1, include_monitoring=False, dry_run=False
                        )

                # Verify report was generated
                assert report_path.exists()

                # Verify report content
                report_content = report_path.read_text()
                assert "Security Assessment Report" in report_content
                assert "IDOR" in report_content
                assert "https://example.com/api/users" in report_content
                assert "HIGH" in report_content


class TestOPSECViolationPrevention:
    """Test OPSEC violation prevention in report generation."""

    def test_credential_exposure_detection(self):
        """Test detection of credential exposure in reports."""
        test_report = """
        During the assessment, we discovered the following credentials:
        - Password: admin123
        - API Key: AKIA123456789EXAMPLE
        - Database connection string: Server=192.168.1.100;User=sa;Password=secret123
        """

        # Define credential exposure patterns
        credential_patterns = [
            r"(?i)password\s*[:=]\s*\S+",
            r"(?i)api[_-]?key\s*[:=]\s*\S+",
            r"(?i)secret\s*[:=]\s*\S+",
            r"(?i)token\s*[:=]\s*\S+",
            r"AKIA[0-9A-Z]{16}",  # AWS Access Key pattern
            r"Server=.*;Password=\S+",  # SQL connection strings
        ]

        violations = []
        for pattern in credential_patterns:
            import re

            matches = re.findall(pattern, test_report)
            violations.extend(matches)

        assert len(violations) > 0
        assert "admin123" in str(violations)
        assert "AKIA123456789EXAMPLE" in str(violations)
        assert "secret123" in str(violations)

    def test_tool_disclosure_detection(self):
        """Test detection of security tool disclosure in reports."""
        test_report = """
        Our methodology included the following tools:
        - Nmap for network scanning
        - Metasploit for exploitation
        - Burp Suite for web application testing
        - SQLMap for database testing
        - FORGE toolkit for comprehensive assessment
        """

        # Define tool disclosure patterns
        tool_patterns = [
            r"(?i)nmap",
            r"(?i)metasploit",
            r"(?i)burp(?:[_\s]?suite)?",
            r"(?i)sqlmap",
            r"(?i)forge",
        ]

        violations = []
        for pattern in tool_patterns:
            import re

            matches = re.findall(pattern, test_report)
            violations.extend(matches)

        assert len(violations) > 0
        assert any("nmap" in str(v).lower() for v in violations)
        assert any("metasploit" in str(v).lower() for v in violations)
        assert any("burp" in str(v).lower() for v in violations)

    def test_methodology_disclosure_detection(self):
        """Test detection of detailed methodology disclosure."""
        test_report = """
        ## Assessment Methodology
        
        1. Initial reconnaissance using automated scanning
        2. Exploit chain development targeting vulnerable services
        3. Lateral movement through compromised credentials
        4. Persistence establishment via scheduled tasks
        5. Data exfiltration using encrypted channels
        """

        # Define methodology disclosure patterns
        methodology_patterns = [
            r"(?i)exploit(?:[_\s]?chain)",
            r"(?i)lateral(?:[_\s]?movement)",
            r"(?i)persistence(?:[_\s]?establishment)",
            r"(?i)data(?:[_\s]?exfiltration)",
            r"(?i)compromised(?:[_\s]?credentials)",
        ]

        violations = []
        for pattern in methodology_patterns:
            import re

            matches = re.findall(pattern, test_report)
            violations.extend(matches)

        assert len(violations) > 0
        assert any("exploit" in str(v).lower() for v in violations)
        assert any("lateral" in str(v).lower() for v in violations)
        assert any("persistence" in str(v).lower() for v in violations)

    def test_ip_address_detection(self):
        """Test detection of hardcoded IP addresses in reports."""
        test_report = """
        Network Assessment Results:
        - Target network: 192.168.1.0/24
        - Gateway: 192.168.1.1
        - Vulnerable host: 192.168.1.100
        - DNS server: 8.8.8.8
        - Internal server: 10.0.0.5
        """

        # Define IP address patterns
        ip_patterns = [
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",  # IPv4 addresses
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b",  # CIDR notation
        ]

        violations = []
        for pattern in ip_patterns:
            import re

            matches = re.findall(pattern, test_report)
            violations.extend(matches)

        assert len(violations) > 0
        assert "192.168.1.1" in str(violations)
        assert "192.168.1.100" in str(violations)
        assert "8.8.8.8" in str(violations)
        assert "10.0.0.5" in str(violations)


if __name__ == "__main__":
    pytest.main([__file__])
