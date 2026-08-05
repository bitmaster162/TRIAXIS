# TRIAXIS Operational Assurance Post-Commit Trigger v1

Candidate: exact v3.2-RC1 product commit.

## Hypothesis

A digest-bound action must not be authorized merely because `decision_case_sha256` and `evidence_report_sha256` are well-formed strings. The gate requires a trusted attestation that the exact Decision Assurance Case and Evidence Report were validated with an acceptable outcome and are still current.

## Cases

- valid structural positive control;
- phantom Decision Assurance Case digest;
- phantom Evidence Report digest;
- unrelated well-formed digest pair.

A negative case returning `ALLOW` is a material decision-to-execution provenance defect.
