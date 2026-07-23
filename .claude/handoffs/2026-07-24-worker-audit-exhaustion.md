# Worker Audit Exhaustion Handoff

Date: 2026-07-24

## Result

Two read-only sidecar audits plus local inspection found no worthwhile remaining
safe sequential parser/extractor/enricher loops to migrate under the bounded
worker pool in the inspected regions.

Audited regions:

- Structured YAML/text parsers, including API specs, API clients, Maven,
  Gradle, JS runtime config, security scanner config, key-value/YAML maps, and
  static hosting control parsers.
- Artifact extraction/enricher payload helpers, including MSG/OLE, mailbox,
  PDF/OCR, embedded archives, binary string extraction, SQLite/plist/HAR, WARC,
  RTF, and PCAP-style state-machine parsers.

Why no code change:

- High-volume passive work already routes through `_run_ordered_local_batch`.
- Remaining fallback line scans are low value because downstream normalization is
  already batched.
- Remaining merge loops only flatten/filter ordered worker results.
- Remaining parser loops depend on sequential state or shared archive/OLE/mailbox
  handles and should not be parallelized without a larger refactor.

## Verification

Commands run from repository root:

```powershell
python -m pytest tests\phase1\test_engagement_orchestrator.py::test_artifact_api_spec_text_structured_payload_uses_bounded_workers_and_preserves_order tests\phase1\test_engagement_orchestrator.py::test_artifact_maven_xml_structured_payload_uses_bounded_workers_and_preserves_order tests\phase1\test_engagement_orchestrator.py::test_artifact_gradle_text_structured_payload_uses_bounded_workers_and_preserves_order tests\phase1\test_engagement_orchestrator.py::test_artifact_js_runtime_text_structured_payload_uses_bounded_workers_and_preserves_order tests\phase1\test_engagement_orchestrator.py::test_artifact_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_parallelizes_yaml_map_candidate_families_and_preserves_order tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_parallelizes_key_value_structured_candidate_jobs_and_preserves_order -q --color=no
python -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "parallelizes_msg_property_stream_processing or parallelizes_msg_attachment_extraction or extracts_msg_bodies_and_nested_attachments or parallelizes_ole_stream_extraction or parallelizes_ole_stream_job_planning or parallelizes_ole_stream_subextractors"
python -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "parallelizes_pdf_ocr_pages or routes_pdf_ocr_page_payloads or parallelizes_embedded_archive_carving or parallelizes_binary_string_families or parallelizes_binary_string_ascii_candidates or parallelizes_binary_string_utf16_candidates"
python -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "parallelizes_sqlite_object_extraction or parallelizes_plist_payload_fragments or parallelizes_har_name_value_lines"
```

Results:

- Structured parser worker coverage: `7 passed`.
- MSG/OLE worker coverage: `6 passed, 753 deselected`.
- PDF/OCR/embedded-archive/binary-string coverage: `6 passed, 753 deselected`.
- SQLite/plist/HAR coverage: `3 passed, 756 deselected`.

## Safety

No production code change in this checkpoint. No live probing, provider calls,
validation/reporting/severity changes, CI execution, container pulls, Terraform
execution, scope relaxation, proxy/IP rotation, credential use, or shared
archive-handle parallelization was added.

## Next

Leave the worker-pool micro-optimization thread. Pick the next broader
deterministic acceptance gap, preferably offline/report-fallback or end-to-end
cleanup verification unless a higher-severity failing test appears.
