# E002-R1 EVIDENCE INVALIDATION RECEIPT

WORK ORDER ID: `TRIAXIS-WO-AGY-GH-002-E002-R2`  
TIMESTAMP (UTC): `2026-08-08T01:51:30Z`  
RECLASSIFICATION: `E002-R1 = INVALIDATED_BY_OPERATOR_REVIEW` / `INVALID_EXECUTION_EVIDENCE`

---

## 1. Reason for Invalidation

Independent GitHub review of the E002-R1 submission identified critical execution defects where process invocation failures were masked as authorization denials, and synthetic/hard-coded values were recorded instead of live runtime outputs.

---

## 2. Itemized Defects Identified

1. **Cedar CLI Execution Error Masked**: Cedar runtime receipt contained `process_exit_code=127` (command not found due to WSL path nesting issue in Python wrapper) with empty stdout.
2. **OPA Execution Error Masked**: OPA runtime receipt contained `process_exit_code=127` with empty stdout.
3. **Invalid Fail-Closed Conversion**: Missing command output and process exit code 127 were converted into authorization `DENY`, allowing execution failures to falsely appear as authorization refusal.
4. **OpenFGA Synthetic Decisions**: OpenFGA results assigned `actual_decision = expected` without executing real HTTP/gRPC Check requests against a live OpenFGA server.
5. **Static Multi-PDP Composition Table**: Multi-PDP composition receipt (Scenarios A–H) was generated from a static Markdown table rather than live runtime invocations.
6. **Synthetic Provenance Hashes**: Provenance values included hard-coded strings (including empty-file hash `e3b0c442...`) rather than actual policy byte hashes and live store/model IDs.
7. **Flawed Final Adjudication**: Final adjudication incorrectly claimed 100% real-runtime execution and verified auditability based on invalid receipt data.

---

## 3. Preserved Evidence Lineage

Per Section 8 of Work Order `E002-R2`, all R1 receipt files under `research/epoch-001/E002/receipts/r1/` are preserved as historical failed evidence and marked `INVALIDATED_BY_OPERATOR_REVIEW`.

All superseding valid evidence is produced by the E002-R2 execution runner and recorded under `research/epoch-001/E002/receipts/r2/`.
