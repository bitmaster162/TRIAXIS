# TRIAXIS v3.2-RC1 post-commit failure evidence

Candidate commit: `1daa9b342be36c16b77e7e7b29d75ed6e8398fd7`
Candidate tree: `af26508be20bc9c4590e495dd5e6a9a41813678d`
Protocol: `TRIAXIS_OPERATIONAL_ASSURANCE_POSTCOMMIT_TRIGGER_v1`

Result: **FAIL (1/4 PASS, 3/4 FAIL)**.

Material defect: the v3.2 action gate validates that `decision_case_sha256` and
`evidence_report_sha256` are syntactically valid SHA-256 values, but it does not
require a trusted PASS attestation binding the exact Decision Assurance Case to
the exact Evidence Report. As a result, arbitrary or unrelated digests can be
laundered into an otherwise valid action envelope and receive `ALLOW`.

This directory freezes the exact post-product evidence before any corrective
implementation is committed.
