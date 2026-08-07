# E002 — Policy Engine Shootout: Cedar vs OPA vs OpenFGA vs AuthZEN

## Overview
This research slice evaluates four authorization policy technologies (Cedar, Open Policy Agent, OpenFGA, AuthZEN) against the requirements of the TRIAXIS continuity operating system.

## Primary Question
Which architecture best supports bounded, auditable, fail-closed authorization for:
`PRINCIPAL × ACTION × RESOURCE × CONTEXT × DELEGATION × POLICY_LIFECYCLE`
without creating unnecessary authority or coupling?

## Primary-Source Executed Versions
- **Cedar (AWS)**: `v4.12.0` (CLI `cedar-policy-cli 4.1.0` / Rust `cedar-policy 4.12.0`, Apache-2.0)
- **OPA (CNCF)**: `v1.0.0` / `v1.19.0` (`opa` binary, Rego v1, Apache-2.0)
- **OpenFGA (CNCF)**: `v1.8.3` (Server `openfga v1.8.3`, CLI `fga v0.6.3`, Apache-2.0)
- **AuthZEN (OIDF)**: `Authorization API 1.0` (Final Specification 1.0, OpenID IPR / Apache-2.0)

## Directory Structure
- `README.md` — Experiment summary & navigation
- `QUESTION.md` — Research thesis & evaluation criteria
- `PRIOR_ART.md` — Background & candidate classifications
- `COMMON_CORPUS.md` — 20-case engine-neutral authorization corpus
- `THREAT_MODEL.md` — Authorization threat vectors & mitigations
- `EXPERIMENT.md` — Test methodology & harness architecture
- `EXPECTED_RESULTS.md` — Pre-execution expected outcomes
- `RESULTS.md` — Executed benchmark & test results
- `SEMANTIC_MATRIX.md` — Expressiveness & semantic fit matrix
- `FAIL_CLOSED_MATRIX.md` — Fail-closed behavior under fault modes
- `PERFORMANCE.md` — Evaluated latency & throughput profiles
- `ADVERSARIAL_REVIEW.md` — 12 mandatory challenges & vulnerabilities
- `ADJUDICATION.md` — Per-candidate & overall architectural verdicts
- `LICENSE_IP_REVIEW.md` — Open source license & IP assessment
- `corpus/` — Common corpus JSON definition
- `prototype/` — Executable test scripts for Cedar, OPA, OpenFGA, AuthZEN
- `reproduce/` — Full reproduction test suite (`run_e002_shootout.py`)
- `receipts/` — Raw execution receipts & logs

**PRODUCT_INTEGRATION**: `false` (All research is isolated under `research/epoch-001/E002/`)
