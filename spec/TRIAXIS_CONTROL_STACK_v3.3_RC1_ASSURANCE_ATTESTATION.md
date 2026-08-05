# TRIAXIS Control Stack v3.3-RC1 — Assurance Attestation Binding

## Status

- Specification: Release Candidate
- Implementation: Partial, deterministic local reference implementation
- Production qualified: No
- External side effects: Not implied

## Material defect closed

The exact v3.2-RC1 product accepted any well-formed values in
`decision_case_sha256` and `evidence_report_sha256`. It did not require evidence
that those exact artifacts had actually passed the Decision Assurance process.
A caller could therefore launder arbitrary digests into an otherwise valid
action envelope.

## New contract

`TRIAXIS_ASSURANCE_PASS_ATTESTATION_v1` binds:

- `attestation_id`;
- external `issuer_id` and `trust_domain`;
- exact `subject_id`;
- exact `decision_case_sha256`;
- exact `evidence_report_sha256`;
- `assurance_status=PASS`;
- synthesis decision `ACCEPT` or `ACCEPT_WITH_CONTROLS`;
- attestation level;
- issuance and expiry window;
- canonical attestation digest.

The action envelope is bumped to
`TRIAXIS_ACTION_ASSURANCE_ENVELOPE_v2` and includes the complete attestation.
The action scope and authorization token bind its exact digest.

## Gate rules

1. Missing attestation -> `DENY`.
2. Non-PASS assurance status -> `DENY`.
3. Non-accepting synthesis decision -> `DENY`.
4. Subject mismatch -> `DENY`.
5. Decision-case digest mismatch -> `DENY`.
6. Evidence-report digest mismatch -> `DENY`.
7. Future or expired attestation -> `DENY`.
8. Issuer absent from the external trust registry -> `DENY`.
9. Issuer registered under another trust domain -> `DENY`.
10. The trusted issuer registry is an input to the deterministic gate, not an
    LLM-generated fact.

## Invariants added

### I21 Assurance passage binding

No action may be authorized unless a trusted attestation binds the exact
Decision Assurance Case and Evidence Report referenced by the action.

### I22 External issuer trust

Canonical digest integrity does not establish issuer authenticity. Authorization
requires an out-of-band trusted issuer/trust-domain registry.

### I23 Synthesis non-authority

A synthesis result can be attested as accepted, but cannot mint authority. The
policy gate independently evaluates capability, target, state, risk, approvals,
nonce and expiry.

### I24 Assurance freshness

An expired or future-dated assurance attestation cannot authorize execution.

## Explicit boundary

The reference implementation uses canonical SHA-256 sealing plus an external
issuer registry supplied by the caller. It does **not** yet implement KMS/PKI
signature verification, hardware roots of trust, transparency logs or remote
attestation. Those remain production P0 requirements.
