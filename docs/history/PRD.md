# Product Requirements Document (PRD)

## Executive Summary
FORGE Toolkit (v7.2) is a modular, CPU-optimized, full-spectrum offensive security platform designed for authorized red team operations. The system orchestrates extensive reconnaissance, OSINT gathering, evasion, exploit correlation, and post-exploitation reporting, all while strictly adhering to rigorous operational security (OPSEC) guidelines. It ensures data confidentiality at rest through AES-256-GCM encryption (pycryptodome, PBKDF2-HMAC-SHA256 key derivation) and safeguards operator identity using strict network proximity controls.

## System Architecture
The FORGE architecture is divided into a CLI-based operator interface and a decentralized job and state management backend:
- **Phase Router / CLI:** Built with Typer. Phase modules are lazy-loaded to ensure immediate CLI responsiveness (<1s latency).
- **Web Interface:** Built on FastAPI/Uvicorn, serving orchestration APIs.
- **Data Persistence:** SQLite database. Utilizes FTS5 virtual tables for rapid text search. Sensitive fields are written out completely encrypted.
- **Distributed Workflow Pipeline:** Incorporates a Redis-backed queue logic. Sub-tasks coordinate using a scheduled worker loop enabling decoupled processing.
- **Reporting System:** Embedded offline LLM integration via `llama-cpp-python` to generate analytical summaries.

## Feature Matrix
- **Phase 0 (Knowledge Base ETL):** Sync offline NVD, LOLBAS, GTFOBins, and Exploit-DB datasets.
- **Phase 1 (Reconnaissance):** Interactive wizard, port scanning, subdomain enumeration, and asynchronous web crawling.
- **Phase 2 (Intelligence Operations):** OSINT capabilities connecting to DeHashed, XposedOrNot, and GitHub/GitLab (for API keys). Features explicit OPSEC validation routing.
- **Phase 3 (Payload Preparation):** Polymorphic obfuscation pipeline with Base64, XOR, GZIP, and character insertion mechanics. Generates templates for Windows, Linux, and macOS.
- **Phase 4 (Exploit & Cloud Correlation):** Maps service banners to Exploit-DB IDs. Includes passive web configuration scanning and deep cloud capability testing across Azure, AWS, Supabase, and Firebase environments. Generates abstract attack chains.
- **Phase 5 (Advanced Post-Exploitation):** Includes C2 agent orchestration, data exfiltration, lateral movement, and persistence deployment using predefined LOLBins.
- **Phase 6 (Reporting):** Automated feedback loop testing against large language models (defaulting to offline LLMs like `qwen2.5-1.5b`) capable of validating output chains before packaging into actionable reports.

## Security & Performance
- **Operator Strict Network Guard:** Application supports a `FORGE_OFFLINE_STRICT` environment lock that natively hijacks standard Python socket modules to prevent any accidental external traffic leakage.
- **Cryptographic Foundations:** The system demands an explicit operator-generated key combination `FORGE_ENGAGEMENT_KEY`. Sensitive fields are encrypted with AES-256-GCM via `pycryptodome` (PBKDF2-HMAC-SHA256 key derivation). No plaintext passwords or tokens are stored persistently on disks. (Note: migration to native `age` library is planned; the interface in `forge.opsec.crypto` is stable.)
- **Safe Mode Design:** Setting `FORGE_SAFE_MODE` to `1` halts memory-invasive features (e.g., payload injection and post-shell operations) to bypass traditional detection mechanisms during pure reconnaissance activities.
- **Performance Constraints:** Database utilizes WAL mapping. Distributed queues and scheduling logic guarantee large-scale OSINT checks run in non-blocking event loops, balancing resource throughput against active network rate limiters.

## Non-Functional Requirements
- **OPSEC Logging:** Every modular action routes correctly through an `audit_log` with operator tracking functionality enabled by default.
- **Scalability:** Local capabilities scale vertically with available threads/Redis slots.
- **Portability:** Supported on standard Windows, Linux, and macOS runtimes using cross platform Python environments. No domain-administrative execution is implicitly required.
